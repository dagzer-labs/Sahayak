use crate::{
    BusinessCommand, CategorySelection, ContactMode, ContactSessionLimit, ConversationContext,
    ConversationDisposition, ConversationState, LocalServiceMode, ProfessionalCommand,
    ProfessionalFlowMode, ProfessionalResumeStep, ProfessionalState, ProfessionalStatus,
    ProfileFieldCode, ReplyControls, ReplySpec, ServiceCategory, ServiceRadius, ServiceSkill,
    SessionChange, SessionSnapshot, TurnPlan, UserInput, render::professional_reply,
};
use sahayak_domain::ProfessionalDisplayName;
use sahayak_localization::{Locale, Localizer, MessageKey};

pub(crate) fn entry_state(view: &crate::ProfessionalView) -> ProfessionalState {
    match view.status {
        ProfessionalStatus::NotStarted => ProfessionalState::DisplayNameInput {
            mode: ProfessionalFlowMode::Initial,
        },
        ProfessionalStatus::Draft => resume_state(view, ProfessionalFlowMode::Initial),
        ProfessionalStatus::ChangesRequested
        | ProfessionalStatus::Rejected
        | ProfessionalStatus::Hidden => ProfessionalState::Status,
        ProfessionalStatus::PendingReview | ProfessionalStatus::Approved => {
            ProfessionalState::Status
        }
    }
}

pub(crate) fn decide(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    state: &ProfessionalState,
    input: &UserInput,
) -> TurnPlan {
    match state {
        ProfessionalState::DisplayNameInput { mode } => {
            display_name_input(localizer, context, session, *mode, input)
        }
        ProfessionalState::DisplayNameConfirm { mode } => {
            display_name_confirm(localizer, context, session, *mode, input)
        }
        ProfessionalState::Categories { mode, selected } => {
            categories(localizer, context, session, *mode, *selected, input)
        }
        ProfessionalState::Skills {
            mode,
            categories,
            category,
            selected,
        } => skills(
            localizer,
            context,
            session,
            *mode,
            *categories,
            *category,
            selected,
            input,
        ),
        ProfessionalState::ServiceArea { mode, categories } => {
            service_area(localizer, context, session, *mode, *categories, input)
        }
        ProfessionalState::Location { mode, categories } => {
            location(localizer, context, session, *mode, *categories, input)
        }
        ProfessionalState::Radius { mode, categories } => {
            radius(localizer, context, session, *mode, *categories, input)
        }
        ProfessionalState::Languages {
            mode,
            categories,
            selected,
        } => languages(
            localizer,
            context,
            session,
            *mode,
            *categories,
            selected,
            input,
        ),
        ProfessionalState::ContactMode {
            mode,
            categories,
            category,
        } => contact_mode(
            localizer,
            context,
            session,
            *mode,
            *categories,
            *category,
            input,
        ),
        ProfessionalState::ContactLimit { mode } => {
            contact_limit(localizer, context, session, *mode, input)
        }
        ProfessionalState::Photo { mode } => photo(localizer, context, session, *mode, input),
        ProfessionalState::Disclosure { mode } => {
            disclosure(localizer, context, session, *mode, input)
        }
        ProfessionalState::Consent { mode, version, .. } => {
            consent(localizer, context, session, *mode, *version, input)
        }
        ProfessionalState::Summary { mode } => summary(localizer, context, session, *mode, input),
        ProfessionalState::Status => status(localizer, context, session, input),
        ProfessionalState::EditMenu => edit(localizer, context, session, input),
    }
}

fn display_name_input(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    input: &UserInput,
) -> TurnPlan {
    if let UserInput::Text(text) = input
        && let Ok(display_name) = ProfessionalDisplayName::parse(text.value().to_owned())
    {
        let display_name = display_name.into_string();
        return advance(
            localizer,
            context,
            session,
            ProfessionalState::DisplayNameConfirm { mode },
            Some(ProfessionalCommand::StageDisplayName { display_name }),
            Some(text.value()),
            ConversationDisposition::Applied,
        );
    }
    unexpected(
        localizer,
        context,
        session,
        MessageKey::PRO_NAME_INVALID_BODY,
    )
}

fn display_name_confirm(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    input: &UserInput,
) -> TurnPlan {
    match action(input) {
        Some("pro.name.confirm") => {
            let next = if mode == ProfessionalFlowMode::Initial {
                ProfessionalState::Categories {
                    mode,
                    selected: categories_from_view(context),
                }
            } else {
                ProfessionalState::Disclosure { mode }
            };
            advance(
                localizer,
                context,
                session,
                next,
                Some(ProfessionalCommand::ConfirmDisplayName {
                    expected_version: context.professional.version,
                }),
                None,
                ConversationDisposition::Applied,
            )
        }
        Some("pro.name.change") => advance(
            localizer,
            context,
            session,
            ProfessionalState::DisplayNameInput { mode },
            None,
            None,
            ConversationDisposition::Applied,
        ),
        _ => unknown(localizer, context, session),
    }
}

fn categories(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    selected: CategorySelection,
    input: &UserInput,
) -> TurnPlan {
    let toggled = match action(input) {
        Some("pro.category.plumber") => Some(selected.toggled(ServiceCategory::Plumber)),
        Some("pro.category.electrician") => Some(selected.toggled(ServiceCategory::Electrician)),
        _ => None,
    };
    if let Some(selected) = toggled {
        return advance(
            localizer,
            context,
            session,
            ProfessionalState::Categories { mode, selected },
            None,
            None,
            ConversationDisposition::Applied,
        );
    }
    if action(input) == Some("pro.category.done") {
        if selected.is_empty() {
            return unexpected(
                localizer,
                context,
                session,
                MessageKey::PRO_SELECTION_REQUIRED_BODY,
            );
        }
        let category = first_category(selected);
        let skills = skills_from_view(context, category);
        return advance(
            localizer,
            context,
            session,
            ProfessionalState::Skills {
                mode,
                categories: selected,
                category,
                selected: skills,
            },
            Some(ProfessionalCommand::SetCategories {
                categories: selected,
            }),
            None,
            ConversationDisposition::Applied,
        );
    }
    unknown(localizer, context, session)
}

#[allow(clippy::too_many_arguments)]
fn skills(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    categories: CategorySelection,
    category: ServiceCategory,
    selected: &[ServiceSkill],
    input: &UserInput,
) -> TurnPlan {
    if let Some(skill) = skill_from_action(action(input))
        && skill.category() == category
    {
        let selected = toggled_value(selected, skill);
        return advance(
            localizer,
            context,
            session,
            ProfessionalState::Skills {
                mode,
                categories,
                category,
                selected,
            },
            None,
            None,
            ConversationDisposition::Applied,
        );
    }
    if action(input) == Some("pro.skill.done") {
        if selected.is_empty() {
            return unexpected(
                localizer,
                context,
                session,
                MessageKey::PRO_SELECTION_REQUIRED_BODY,
            );
        }
        let next = if category == ServiceCategory::Plumber && categories.electrician {
            ProfessionalState::Skills {
                mode,
                categories,
                category: ServiceCategory::Electrician,
                selected: skills_from_view(context, ServiceCategory::Electrician),
            }
        } else if mode == ProfessionalFlowMode::Initial {
            ProfessionalState::ServiceArea { mode, categories }
        } else {
            ProfessionalState::Disclosure { mode }
        };
        return advance(
            localizer,
            context,
            session,
            next,
            Some(ProfessionalCommand::SetSkills {
                category,
                skills: selected.to_vec(),
            }),
            None,
            ConversationDisposition::Applied,
        );
    }
    unknown(localizer, context, session)
}

fn service_area(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    categories: CategorySelection,
    input: &UserInput,
) -> TurnPlan {
    let selected = match action(input) {
        Some("pro.area.travel") => Some(LocalServiceMode::TravelToCustomer),
        Some("pro.area.visits") => Some(LocalServiceMode::CustomerVisits),
        Some("pro.area.both") => Some(LocalServiceMode::Both),
        _ => None,
    };
    selected.map_or_else(
        || unknown(localizer, context, session),
        |selected| {
            advance(
                localizer,
                context,
                session,
                ProfessionalState::Radius { mode, categories },
                Some(ProfessionalCommand::SetLocalMode { mode: selected }),
                None,
                ConversationDisposition::Applied,
            )
        },
    )
}

fn location(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    categories: CategorySelection,
    input: &UserInput,
) -> TurnPlan {
    if matches!(input, UserInput::Location) {
        let next = if mode == ProfessionalFlowMode::Initial {
            ProfessionalState::Languages {
                mode,
                categories,
                selected: languages_from_view(context),
            }
        } else {
            ProfessionalState::Disclosure { mode }
        };
        return advance(
            localizer,
            context,
            session,
            next,
            Some(ProfessionalCommand::CurrentInboundLocation),
            None,
            ConversationDisposition::Applied,
        );
    }
    unknown(localizer, context, session)
}

fn radius(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    categories: CategorySelection,
    input: &UserInput,
) -> TurnPlan {
    let selected = match action(input) {
        Some("pro.radius.2") => Some(ServiceRadius::Km2),
        Some("pro.radius.5") => Some(ServiceRadius::Km5),
        Some("pro.radius.10") => Some(ServiceRadius::Km10),
        Some("pro.radius.25") => Some(ServiceRadius::Km25),
        _ => None,
    };
    selected.map_or_else(
        || unknown(localizer, context, session),
        |radius| {
            advance(
                localizer,
                context,
                session,
                ProfessionalState::Location { mode, categories },
                Some(ProfessionalCommand::SetRadius { radius }),
                None,
                ConversationDisposition::Applied,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn languages(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    categories: CategorySelection,
    selected: &[Locale],
    input: &UserInput,
) -> TurnPlan {
    let locale = match action(input) {
        Some("pro.language.en") => Some(Locale::EnIn),
        Some("pro.language.hi") => Some(Locale::HiIn),
        Some("pro.language.mr") => Some(Locale::MrIn),
        _ => None,
    };
    if let Some(locale) = locale {
        return advance(
            localizer,
            context,
            session,
            ProfessionalState::Languages {
                mode,
                categories,
                selected: toggled_value(selected, locale),
            },
            None,
            None,
            ConversationDisposition::Applied,
        );
    }
    if action(input) == Some("pro.language.done") {
        if selected.is_empty() {
            return unexpected(
                localizer,
                context,
                session,
                MessageKey::PRO_SELECTION_REQUIRED_BODY,
            );
        }
        let next = if mode == ProfessionalFlowMode::Initial {
            ProfessionalState::ContactMode {
                mode,
                categories,
                category: first_category(categories),
            }
        } else {
            ProfessionalState::Disclosure { mode }
        };
        return advance(
            localizer,
            context,
            session,
            next,
            Some(ProfessionalCommand::SetServiceLanguages {
                locales: selected.to_vec(),
            }),
            None,
            ConversationDisposition::Applied,
        );
    }
    unknown(localizer, context, session)
}

#[allow(clippy::too_many_arguments)]
fn contact_mode(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    categories: CategorySelection,
    category: ServiceCategory,
    input: &UserInput,
) -> TurnPlan {
    let selected = match action(input) {
        Some("pro.contact.direct") => Some(ContactMode::Direct),
        Some("pro.contact.approval") => Some(ContactMode::ApprovalRequired),
        _ => None,
    };
    selected.map_or_else(
        || unknown(localizer, context, session),
        |contact_mode| {
            let next = if category == ServiceCategory::Plumber && categories.electrician {
                ProfessionalState::ContactMode {
                    mode,
                    categories,
                    category: ServiceCategory::Electrician,
                }
            } else {
                ProfessionalState::ContactLimit { mode }
            };
            advance(
                localizer,
                context,
                session,
                next,
                Some(ProfessionalCommand::SetContactMode {
                    category,
                    mode: contact_mode,
                }),
                None,
                ConversationDisposition::Applied,
            )
        },
    )
}

fn contact_limit(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    input: &UserInput,
) -> TurnPlan {
    let selected = match action(input) {
        Some("pro.limit.1") => Some(ContactSessionLimit::One),
        Some("pro.limit.3") => Some(ContactSessionLimit::Three),
        Some("pro.limit.5") => Some(ContactSessionLimit::Five),
        Some("pro.limit.10") => Some(ContactSessionLimit::Ten),
        _ => None,
    };
    selected.map_or_else(
        || unknown(localizer, context, session),
        |limit| {
            let next = if mode == ProfessionalFlowMode::Initial {
                ProfessionalState::Photo { mode }
            } else {
                ProfessionalState::Disclosure { mode }
            };
            advance(
                localizer,
                context,
                session,
                next,
                Some(ProfessionalCommand::SetContactSessionLimit { limit }),
                None,
                ConversationDisposition::Applied,
            )
        },
    )
}

fn photo(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    input: &UserInput,
) -> TurnPlan {
    let command = match input {
        UserInput::Media => Some(ProfessionalCommand::CurrentInboundMedia),
        _ => match action(input) {
            Some("pro.photo.skip") => Some(ProfessionalCommand::SkipPhoto),
            Some("pro.photo.remove") => Some(ProfessionalCommand::RemovePhoto),
            _ => None,
        },
    };
    command.map_or_else(
        || unknown(localizer, context, session),
        |command| {
            advance(
                localizer,
                context,
                session,
                ProfessionalState::Disclosure { mode },
                Some(command),
                None,
                ConversationDisposition::Applied,
            )
        },
    )
}

fn disclosure(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    input: &UserInput,
) -> TurnPlan {
    if action(input) == Some("pro.disclosure.continue") {
        return advance(
            localizer,
            context,
            session,
            ProfessionalState::Summary { mode },
            None,
            None,
            ConversationDisposition::Applied,
        );
    }
    unknown(localizer, context, session)
}

fn consent(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    version: u16,
    input: &UserInput,
) -> TurnPlan {
    if action(input) == Some("pro.consent.accept") {
        return advance(
            localizer,
            context,
            session,
            ProfessionalState::Summary { mode },
            Some(ProfessionalCommand::AcceptConsent { version }),
            None,
            ConversationDisposition::Applied,
        );
    }
    unknown(localizer, context, session)
}

fn summary(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    mode: ProfessionalFlowMode,
    input: &UserInput,
) -> TurnPlan {
    match action(input) {
        Some("pro.summary.submit")
            if context.professional.accepted_consent_version
                == Some(crate::PROFESSIONAL_CONSENT_VERSION) =>
        {
            let mut plan = advance(
                localizer,
                context,
                session,
                ProfessionalState::Status,
                Some(ProfessionalCommand::SubmitForReview {
                    expected_version: context.professional.version,
                    edited: mode == ProfessionalFlowMode::Edit,
                }),
                None,
                ConversationDisposition::Applied,
            );
            plan.reply = ReplySpec {
                body: localizer
                    .text(session.locale, MessageKey::PRO_SUBMITTED_BODY)
                    .to_owned(),
                controls: ReplyControls::None,
            };
            plan
        }
        Some("pro.summary.submit") => advance(
            localizer,
            context,
            session,
            ProfessionalState::Consent {
                mode,
                version: crate::PROFESSIONAL_CONSENT_VERSION,
                document_set_digest: None,
            },
            None,
            None,
            ConversationDisposition::Applied,
        ),
        Some("pro.summary.edit") => advance(
            localizer,
            context,
            session,
            ProfessionalState::EditMenu,
            None,
            None,
            ConversationDisposition::Applied,
        ),
        _ => unknown(localizer, context, session),
    }
}

fn status(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    input: &UserInput,
) -> TurnPlan {
    match action(input) {
        Some("pro.status.resume") => {
            let mode = if context.professional.status == ProfessionalStatus::Draft {
                ProfessionalFlowMode::Initial
            } else {
                ProfessionalFlowMode::Edit
            };
            advance(
                localizer,
                context,
                session,
                resume_state(&context.professional, mode),
                None,
                None,
                ConversationDisposition::Applied,
            )
        }
        Some("pro.status.edit") if context.professional.status == ProfessionalStatus::Approved => {
            advance(
                localizer,
                context,
                session,
                ProfessionalState::EditMenu,
                None,
                None,
                ConversationDisposition::Applied,
            )
        }
        _ => unknown(localizer, context, session),
    }
}

fn edit(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    input: &UserInput,
) -> TurnPlan {
    let mode = ProfessionalFlowMode::Edit;
    let categories = categories_from_view(context);
    let next = match action(input) {
        Some("pro.edit.name") => Some(ProfessionalState::DisplayNameInput { mode }),
        Some("pro.edit.services") => Some(ProfessionalState::Categories {
            mode,
            selected: categories,
        }),
        Some("pro.edit.area") => Some(ProfessionalState::ServiceArea { mode, categories }),
        Some("pro.edit.languages") => Some(ProfessionalState::Languages {
            mode,
            categories,
            selected: languages_from_view(context),
        }),
        Some("pro.edit.contact") if !categories.is_empty() => {
            Some(ProfessionalState::ContactMode {
                mode,
                categories,
                category: first_category(categories),
            })
        }
        Some("pro.edit.photo") => Some(ProfessionalState::Photo { mode }),
        _ => None,
    };
    next.map_or_else(
        || unknown(localizer, context, session),
        |next| {
            advance(
                localizer,
                context,
                session,
                next,
                None,
                None,
                ConversationDisposition::Applied,
            )
        },
    )
}

fn resume_state(view: &crate::ProfessionalView, mode: ProfessionalFlowMode) -> ProfessionalState {
    if mode == ProfessionalFlowMode::Edit
        && view.resume_step.is_none()
        && let Some(field) = view.requested_changes.first()
    {
        return edit_state_for_field(view, *field);
    }
    let categories = view
        .summary
        .as_ref()
        .map_or_else(CategorySelection::default, |summary| summary.categories);
    match view
        .resume_step
        .unwrap_or(ProfessionalResumeStep::DisplayName)
    {
        ProfessionalResumeStep::DisplayName => ProfessionalState::DisplayNameInput { mode },
        ProfessionalResumeStep::Categories => ProfessionalState::Categories {
            mode,
            selected: categories,
        },
        ProfessionalResumeStep::Skills if !categories.is_empty() => {
            let category = first_category(categories);
            ProfessionalState::Skills {
                mode,
                categories,
                category,
                selected: view.summary.as_ref().map_or_else(Vec::new, |summary| {
                    summary
                        .skills
                        .iter()
                        .copied()
                        .filter(|skill| skill.category() == category)
                        .collect()
                }),
            }
        }
        ProfessionalResumeStep::ServiceArea if !categories.is_empty() => {
            ProfessionalState::ServiceArea { mode, categories }
        }
        ProfessionalResumeStep::Location if !categories.is_empty() => {
            ProfessionalState::Location { mode, categories }
        }
        ProfessionalResumeStep::Radius if !categories.is_empty() => {
            ProfessionalState::Radius { mode, categories }
        }
        ProfessionalResumeStep::Languages if !categories.is_empty() => {
            ProfessionalState::Languages {
                mode,
                categories,
                selected: view
                    .summary
                    .as_ref()
                    .map_or_else(Vec::new, |summary| summary.service_languages.clone()),
            }
        }
        ProfessionalResumeStep::Contact if !categories.is_empty() => {
            ProfessionalState::ContactMode {
                mode,
                categories,
                category: first_category(categories),
            }
        }
        ProfessionalResumeStep::ContactLimit => ProfessionalState::ContactLimit { mode },
        ProfessionalResumeStep::Photo => ProfessionalState::Photo { mode },
        ProfessionalResumeStep::Disclosure => ProfessionalState::Disclosure { mode },
        ProfessionalResumeStep::Consent => ProfessionalState::Consent {
            mode,
            version: crate::PROFESSIONAL_CONSENT_VERSION,
            document_set_digest: None,
        },
        ProfessionalResumeStep::Summary => ProfessionalState::Summary { mode },
        ProfessionalResumeStep::Skills
        | ProfessionalResumeStep::ServiceArea
        | ProfessionalResumeStep::Location
        | ProfessionalResumeStep::Radius
        | ProfessionalResumeStep::Languages
        | ProfessionalResumeStep::Contact => ProfessionalState::Categories {
            mode,
            selected: categories,
        },
    }
}

fn advance(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    next: ProfessionalState,
    command: Option<ProfessionalCommand>,
    prefix: Option<&str>,
    disposition: ConversationDisposition,
) -> TurnPlan {
    let reply = professional_reply(
        localizer,
        session.locale,
        &next,
        &context.professional,
        prefix,
    );
    TurnPlan {
        session_change: SessionChange::Advance {
            session_id: session.id,
            expected_version: session.version,
            next: ConversationState::Professional(next),
        },
        locale_change: None,
        business_command: command.map(BusinessCommand::Professional),
        reply,
        disposition,
    }
}

fn unknown(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
) -> TurnPlan {
    unexpected(localizer, context, session, MessageKey::INPUT_UNKNOWN_BODY)
}

fn unexpected(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    message: MessageKey,
) -> TurnPlan {
    let ConversationState::Professional(state) = &session.state else {
        return advance(
            localizer,
            context,
            session,
            ProfessionalState::Status,
            None,
            Some(localizer.text(session.locale, message)),
            ConversationDisposition::Unexpected,
        );
    };
    advance(
        localizer,
        context,
        session,
        state.clone(),
        None,
        Some(localizer.text(session.locale, message)),
        ConversationDisposition::Unexpected,
    )
}

fn first_category(categories: CategorySelection) -> ServiceCategory {
    if categories.plumber {
        ServiceCategory::Plumber
    } else {
        ServiceCategory::Electrician
    }
}

fn categories_from_view(context: &ConversationContext) -> CategorySelection {
    context
        .professional
        .summary
        .as_ref()
        .map_or_else(CategorySelection::default, |summary| summary.categories)
}

fn skills_from_view(context: &ConversationContext, category: ServiceCategory) -> Vec<ServiceSkill> {
    context
        .professional
        .summary
        .as_ref()
        .map_or_else(Vec::new, |summary| {
            summary
                .skills
                .iter()
                .copied()
                .filter(|skill| skill.category() == category)
                .collect()
        })
}

fn languages_from_view(context: &ConversationContext) -> Vec<Locale> {
    context
        .professional
        .summary
        .as_ref()
        .map_or_else(Vec::new, |summary| summary.service_languages.clone())
}

fn toggled_value<T: Copy + Eq>(selected: &[T], value: T) -> Vec<T> {
    if selected.contains(&value) {
        selected
            .iter()
            .copied()
            .filter(|selected| *selected != value)
            .collect()
    } else {
        let mut values = selected.to_vec();
        values.push(value);
        values
    }
}

fn skill_from_action(action: Option<&str>) -> Option<ServiceSkill> {
    match action {
        Some("pro.skill.leak") => Some(ServiceSkill::LeakRepair),
        Some("pro.skill.fixture") => Some(ServiceSkill::TapAndFixture),
        Some("pro.skill.drain") => Some(ServiceSkill::DrainClearing),
        Some("pro.skill.wiring") => Some(ServiceSkill::HomeWiring),
        Some("pro.skill.switch") => Some(ServiceSkill::SwitchAndSocket),
        Some("pro.skill.fan") => Some(ServiceSkill::FanInstallation),
        _ => None,
    }
}

fn action(input: &UserInput) -> Option<&str> {
    match input {
        UserInput::Action { id, .. } => Some(id.as_str()),
        _ => None,
    }
}

pub(crate) fn edit_state_for_field(
    view: &crate::ProfessionalView,
    field: ProfileFieldCode,
) -> ProfessionalState {
    let mode = ProfessionalFlowMode::Edit;
    let categories = view
        .summary
        .as_ref()
        .map_or_else(CategorySelection::default, |summary| summary.categories);
    match field {
        ProfileFieldCode::DisplayName => ProfessionalState::DisplayNameInput { mode },
        ProfileFieldCode::Services => ProfessionalState::Categories {
            mode,
            selected: categories,
        },
        ProfileFieldCode::ServiceArea => ProfessionalState::ServiceArea { mode, categories },
        ProfileFieldCode::Languages => ProfessionalState::Languages {
            mode,
            categories,
            selected: view
                .summary
                .as_ref()
                .map_or_else(Vec::new, |summary| summary.service_languages.clone()),
        },
        ProfileFieldCode::Contact if !categories.is_empty() => ProfessionalState::ContactMode {
            mode,
            categories,
            category: first_category(categories),
        },
        ProfileFieldCode::Contact | ProfileFieldCode::Photo => ProfessionalState::Photo { mode },
    }
}
