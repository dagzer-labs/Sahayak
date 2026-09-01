use crate::{
    AccountCommand, AdminState, AdminView, AvailabilityIneligibility, AvailabilityState,
    AvailabilityView, BusinessCommand, ConversationContext, ConversationDisposition,
    ConversationState, DiscoveryState, ProfessionalRequestsState, ProfessionalState, ReplySpec,
    SafetyAdminState, SessionChange, SessionTerminalStatus, TrustState, TurnPlan, UserInput,
    administrator, availability, discovery,
    professional::{self},
    render::{
        administrator_reply, help_menu, language_confirmation, language_selection, main_menu,
        more_menu, professional_reply,
    },
    requests, safety_admin, trust,
};
use sahayak_localization::{Locale, LocalizationError, Localizer, MessageKey};
use thiserror::Error;

fn subscription_message(
    localizer: &Localizer,
    locale: Locale,
    billing: &crate::BillingView,
) -> String {
    let (key, payment_url) = match billing {
        crate::BillingView::FreeValue => (MessageKey::BILLING_FREE_BODY, None),
        crate::BillingView::PaymentRequired { hosted_payment_url } => (
            MessageKey::BILLING_PAYMENT_REQUIRED_BODY,
            hosted_payment_url.as_deref(),
        ),
        crate::BillingView::PendingPayment { hosted_payment_url } => (
            MessageKey::BILLING_PENDING_BODY,
            hosted_payment_url.as_deref(),
        ),
        crate::BillingView::Active => (MessageKey::BILLING_ACTIVE_BODY, None),
        crate::BillingView::GracePeriod => (MessageKey::BILLING_GRACE_BODY, None),
        crate::BillingView::Expired => (MessageKey::BILLING_EXPIRED_BODY, None),
        crate::BillingView::ManuallyWaived => (MessageKey::BILLING_WAIVED_BODY, None),
    };
    match payment_url {
        Some(url) => format!("{}\n{url}", localizer.text(locale, key)),
        None => localizer.text(locale, key).to_owned(),
    }
}

/// Conversation engine construction or invariant failure.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Localization(#[from] LocalizationError),
    #[error("conversation state does not match a supported workflow contract")]
    InvalidState,
    #[error("localized conversation output violates channel limits")]
    InvalidRenderedCatalog,
}

/// Pure deterministic conversation engine.
pub struct ConversationEngine {
    localizer: Localizer,
}

impl ConversationEngine {
    /// Loads and validates every locale catalog and representative rendered state.
    pub fn load() -> Result<Self, EngineError> {
        let localizer = Localizer::load()?;
        validate_rendered_catalogs(&localizer)?;
        Ok(Self { localizer })
    }

    /// Decides one turn without database or provider side effects.
    pub fn decide(
        &self,
        context: &ConversationContext,
        input: &UserInput,
    ) -> Result<TurnPlan, EngineError> {
        if !context.availability.is_valid() {
            return Err(EngineError::InvalidState);
        }
        let plan = self.decide_inner(context, input)?;
        validate_reply(&plan.reply)?;
        Ok(plan)
    }

    fn decide_inner(
        &self,
        context: &ConversationContext,
        input: &UserInput,
    ) -> Result<TurnPlan, EngineError> {
        if matches!(input, UserInput::Text(_))
            && let Some(global) = global_command(input)
        {
            return Ok(self.global_plan(context, global));
        }
        let Some(session) = &context.session else {
            return Ok(self.new_session_plan(context));
        };
        if let UserInput::Action { reply_to, .. } = input
            && (session.expected_reply_to.is_none() || *reply_to != session.expected_reply_to)
        {
            let message_locale = match &session.state {
                ConversationState::LocaleConfirm { candidate } => *candidate,
                _ => session.locale,
            };
            return Ok(self.same_state(
                context,
                session,
                Some(
                    self.localizer
                        .text(message_locale, MessageKey::SELECTION_STALE_BODY),
                ),
                ConversationDisposition::Stale,
            ));
        }
        if let ConversationState::Availability(state) = &session.state
            && let Some(observation) = state.observation()
            && observation != context.availability.observation()
        {
            return Ok(availability::stale(&self.localizer, context, session));
        }
        if let Some(global) = global_command(input) {
            return Ok(self.global_plan(context, global));
        }
        match &session.state {
            ConversationState::LocaleChoose => self.locale_choose(context, input),
            ConversationState::LocaleConfirm { candidate } => {
                self.locale_confirm(context, input, *candidate)
            }
            ConversationState::MainShow => self.main(context, input),
            ConversationState::MoreShow => self.more(context, input),
            ConversationState::HelpShow => self.help(context, input),
            ConversationState::Professional(state) => Ok(professional::decide(
                &self.localizer,
                context,
                session,
                state,
                input,
            )),
            ConversationState::Administrator(state) => Ok(administrator::decide(
                &self.localizer,
                context,
                session,
                state,
                input,
            )),
            ConversationState::Availability(state) => Ok(availability::decide(
                &self.localizer,
                context,
                session,
                state,
                input,
            )),
            ConversationState::Discovery(state) => {
                Ok(discovery::decide(&self.localizer, context, state, input))
            }
            ConversationState::ProfessionalRequests(state) => {
                Ok(requests::decide(&self.localizer, context, state, input))
            }
            ConversationState::Trust(state) => {
                Ok(trust::decide(&self.localizer, context, state, input))
            }
            ConversationState::SafetyAdministrator(state) => {
                Ok(safety_admin::decide(&self.localizer, context, state, input))
            }
        }
    }

    fn new_session_plan(&self, context: &ConversationContext) -> TurnPlan {
        match context.confirmed_locale {
            Some(locale) if !context.connections.pending.is_empty() => {
                let state = ProfessionalRequestsState::List;
                TurnPlan {
                    session_change: SessionChange::Create {
                        next: ConversationState::ProfessionalRequests(state.clone()),
                        locale,
                    },
                    locale_change: None,
                    business_command: None,
                    reply: requests::reply(
                        &self.localizer,
                        locale,
                        &state,
                        &context.connections,
                        context.session_expired.then(|| {
                            self.localizer
                                .text(locale, MessageKey::SESSION_EXPIRED_BODY)
                        }),
                    ),
                    disposition: ConversationDisposition::Recovered,
                }
            }
            Some(locale)
                if matches!(
                    context.availability,
                    AvailabilityView::Available(_)
                        | AvailabilityView::Stopped(_)
                        | AvailabilityView::CapacityPaused(_)
                        | AvailabilityView::Expired(_)
                ) =>
            {
                let state = availability::entry_state(context.availability);
                TurnPlan {
                    session_change: SessionChange::Create {
                        next: ConversationState::Availability(state.clone()),
                        locale,
                    },
                    locale_change: None,
                    business_command: None,
                    reply: availability::reply(
                        &self.localizer,
                        locale,
                        &state,
                        context.availability,
                        context.session_expired.then(|| {
                            self.localizer
                                .text(locale, MessageKey::SESSION_EXPIRED_BODY)
                        }),
                    ),
                    disposition: if context.session_expired {
                        ConversationDisposition::Recovered
                    } else {
                        ConversationDisposition::Applied
                    },
                }
            }
            Some(locale)
                if matches!(
                    context.professional.status,
                    crate::ProfessionalStatus::PendingReview
                        | crate::ProfessionalStatus::Approved
                        | crate::ProfessionalStatus::ChangesRequested
                        | crate::ProfessionalStatus::Rejected
                        | crate::ProfessionalStatus::Hidden
                ) =>
            {
                let next = ConversationState::Professional(ProfessionalState::Status);
                TurnPlan {
                    session_change: SessionChange::Create { next, locale },
                    locale_change: None,
                    business_command: None,
                    reply: professional_reply(
                        &self.localizer,
                        locale,
                        &ProfessionalState::Status,
                        &context.professional,
                        context.session_expired.then(|| {
                            self.localizer
                                .text(locale, MessageKey::SESSION_EXPIRED_BODY)
                        }),
                    ),
                    disposition: if context.session_expired {
                        ConversationDisposition::Recovered
                    } else {
                        ConversationDisposition::Applied
                    },
                }
            }
            Some(locale) => TurnPlan {
                session_change: SessionChange::Create {
                    next: ConversationState::MainShow,
                    locale,
                },
                locale_change: None,
                business_command: None,
                reply: main_menu(
                    &self.localizer,
                    locale,
                    context.session_expired.then(|| {
                        self.localizer
                            .text(locale, MessageKey::SESSION_EXPIRED_BODY)
                    }),
                ),
                disposition: if context.session_expired {
                    ConversationDisposition::Recovered
                } else {
                    ConversationDisposition::Applied
                },
            },
            None => TurnPlan {
                session_change: SessionChange::Create {
                    next: ConversationState::LocaleChoose,
                    locale: Locale::EnIn,
                },
                locale_change: None,
                business_command: None,
                reply: language_selection(
                    &self.localizer,
                    context.session_expired.then_some(
                        self.localizer
                            .text(Locale::EnIn, MessageKey::SESSION_EXPIRED_BODY),
                    ),
                ),
                disposition: if context.session_expired {
                    ConversationDisposition::Recovered
                } else {
                    ConversationDisposition::Applied
                },
            },
        }
    }

    fn locale_choose(
        &self,
        context: &ConversationContext,
        input: &UserInput,
    ) -> Result<TurnPlan, EngineError> {
        let session = context.session.as_ref().ok_or(EngineError::InvalidState)?;
        let selected = action(input)
            .and_then(locale_from_action)
            .or_else(|| typed_locale(input));
        if let Some(candidate) = selected {
            return Ok(TurnPlan {
                session_change: SessionChange::Advance {
                    session_id: session.id,
                    expected_version: session.version,
                    next: ConversationState::LocaleConfirm { candidate },
                },
                locale_change: None,
                business_command: None,
                reply: language_confirmation(&self.localizer, candidate, None),
                disposition: ConversationDisposition::Applied,
            });
        }
        Ok(self.same_state(
            context,
            session,
            Some(
                self.localizer
                    .text(Locale::EnIn, MessageKey::INPUT_UNKNOWN_BODY),
            ),
            ConversationDisposition::Unexpected,
        ))
    }

    fn locale_confirm(
        &self,
        context: &ConversationContext,
        input: &UserInput,
        candidate: Locale,
    ) -> Result<TurnPlan, EngineError> {
        let session = context.session.as_ref().ok_or(EngineError::InvalidState)?;
        match action(input) {
            Some("locale.confirm") => Ok(TurnPlan {
                session_change: SessionChange::Replace {
                    session_id: session.id,
                    expected_version: session.version,
                    next: ConversationState::MainShow,
                    locale: candidate,
                    terminal_status: SessionTerminalStatus::Completed,
                    terminal_reason: "locale_confirmed",
                },
                locale_change: Some(candidate),
                business_command: Some(BusinessCommand::Account(AccountCommand::SetLocale {
                    locale: candidate,
                })),
                reply: main_menu(
                    &self.localizer,
                    candidate,
                    Some(
                        self.localizer
                            .text(candidate, MessageKey::LANGUAGE_SAVED_BODY),
                    ),
                ),
                disposition: ConversationDisposition::Applied,
            }),
            Some("locale.change") => Ok(TurnPlan {
                session_change: SessionChange::Advance {
                    session_id: session.id,
                    expected_version: session.version,
                    next: ConversationState::LocaleChoose,
                },
                locale_change: None,
                business_command: None,
                reply: language_selection(&self.localizer, None),
                disposition: ConversationDisposition::Applied,
            }),
            _ => Ok(self.same_state(
                context,
                session,
                Some(
                    self.localizer
                        .text(candidate, MessageKey::INPUT_UNKNOWN_BODY),
                ),
                ConversationDisposition::Unexpected,
            )),
        }
    }

    fn main(
        &self,
        context: &ConversationContext,
        input: &UserInput,
    ) -> Result<TurnPlan, EngineError> {
        let session = context.session.as_ref().ok_or(EngineError::InvalidState)?;
        Ok(match action(input) {
            Some("main.more") => self.replace(
                context,
                session,
                ConversationState::MoreShow,
                more_menu(
                    &self.localizer,
                    session.locale,
                    matches!(context.administrator, AdminView::Allowed(_)),
                    !matches!(
                        context.availability,
                        AvailabilityView::Ineligible(
                            AvailabilityIneligibility::ProfessionalRoleRequired
                        )
                    ),
                    !matches!(
                        context.availability,
                        AvailabilityView::Ineligible(
                            AvailabilityIneligibility::ProfessionalRoleRequired
                        )
                    ),
                    None,
                ),
                SessionTerminalStatus::Completed,
                "open_more",
            ),
            Some("main.find") => self.replace(
                context,
                session,
                ConversationState::Discovery(discovery::entry_state(
                    &context.discovery,
                    &context.connections,
                )),
                discovery::reply(
                    &self.localizer,
                    session.locale,
                    &discovery::entry_state(&context.discovery, &context.connections),
                    &context.discovery,
                    &context.connections,
                    None,
                ),
                SessionTerminalStatus::Completed,
                "open_discovery",
            ),
            Some("main.offer") => {
                let state = professional::entry_state(&context.professional);
                let reply = professional_reply(
                    &self.localizer,
                    session.locale,
                    &state,
                    &context.professional,
                    None,
                );
                self.replace(
                    context,
                    session,
                    ConversationState::Professional(state),
                    reply,
                    SessionTerminalStatus::Completed,
                    "open_professional",
                )
            }
            _ => self.same_state(
                context,
                session,
                Some(
                    self.localizer
                        .text(session.locale, MessageKey::INPUT_UNKNOWN_BODY),
                ),
                ConversationDisposition::Unexpected,
            ),
        })
    }

    fn more(
        &self,
        context: &ConversationContext,
        input: &UserInput,
    ) -> Result<TurnPlan, EngineError> {
        let session = context.session.as_ref().ok_or(EngineError::InvalidState)?;
        Ok(match action(input) {
            Some("more.language") => self.replace(
                context,
                session,
                ConversationState::LocaleChoose,
                language_selection(&self.localizer, None),
                SessionTerminalStatus::Completed,
                "change_language",
            ),
            Some("more.help") => self.replace(
                context,
                session,
                ConversationState::HelpShow,
                help_menu(&self.localizer, session.locale, None),
                SessionTerminalStatus::Completed,
                "open_help",
            ),
            Some("more.admin") => match &context.administrator {
                AdminView::Allowed(_) => {
                    let state = AdminState::Queue { page: 0 };
                    let reply = administrator_reply(
                        &self.localizer,
                        session.locale,
                        &state,
                        &context.administrator,
                        None,
                    );
                    self.replace(
                        context,
                        session,
                        ConversationState::Administrator(state),
                        reply,
                        SessionTerminalStatus::Completed,
                        "open_administrator_review",
                    )
                }
                AdminView::Denied => self.same_state(
                    context,
                    session,
                    Some(
                        self.localizer
                            .text(session.locale, MessageKey::ADMIN_DENIED_BODY),
                    ),
                    ConversationDisposition::Unexpected,
                ),
            },
            Some("more.safety_admin") => match &context.safety_administrator {
                crate::SafetyAdminView::Allowed { .. } => {
                    let state = SafetyAdminState::Queue;
                    self.replace(
                        context,
                        session,
                        ConversationState::SafetyAdministrator(state.clone()),
                        safety_admin::reply(
                            &self.localizer,
                            session.locale,
                            &state,
                            &context.safety_administrator,
                            None,
                        ),
                        SessionTerminalStatus::Completed,
                        "open_safety_reports",
                    )
                }
                crate::SafetyAdminView::Denied => self.same_state(
                    context,
                    session,
                    Some(
                        self.localizer
                            .text(session.locale, MessageKey::ADMIN_DENIED_BODY),
                    ),
                    ConversationDisposition::Unexpected,
                ),
            },
            Some("more.availability") => match context.availability {
                AvailabilityView::Ineligible(
                    AvailabilityIneligibility::ProfessionalRoleRequired,
                ) => self.same_state(
                    context,
                    session,
                    Some(
                        self.localizer
                            .text(session.locale, MessageKey::AVAILABILITY_ROLE_DENIED_BODY),
                    ),
                    ConversationDisposition::Unexpected,
                ),
                availability_view => {
                    let state = availability::entry_state(availability_view);
                    let reply = availability::reply(
                        &self.localizer,
                        session.locale,
                        &state,
                        availability_view,
                        None,
                    );
                    self.replace(
                        context,
                        session,
                        ConversationState::Availability(state),
                        reply,
                        SessionTerminalStatus::Completed,
                        "open_availability",
                    )
                }
            },
            Some("more.contacts") => self.replace(
                context,
                session,
                ConversationState::Discovery(DiscoveryState::Recent),
                discovery::reply(
                    &self.localizer,
                    session.locale,
                    &DiscoveryState::Recent,
                    &context.discovery,
                    &context.connections,
                    None,
                ),
                SessionTerminalStatus::Completed,
                "open_recent_contacts",
            ),
            Some("more.trust") => {
                let state = TrustState::List;
                self.replace(
                    context,
                    session,
                    ConversationState::Trust(state.clone()),
                    trust::reply(
                        &self.localizer,
                        session.locale,
                        &state,
                        &context.trust,
                        None,
                    ),
                    SessionTerminalStatus::Completed,
                    "open_trust_safety",
                )
            }
            Some("more.requests") => {
                if matches!(
                    context.availability,
                    AvailabilityView::Ineligible(
                        AvailabilityIneligibility::ProfessionalRoleRequired
                    )
                ) {
                    self.same_state(
                        context,
                        session,
                        Some(
                            self.localizer
                                .text(session.locale, MessageKey::AVAILABILITY_ROLE_DENIED_BODY),
                        ),
                        ConversationDisposition::Unexpected,
                    )
                } else {
                    let state = ProfessionalRequestsState::List;
                    self.replace(
                        context,
                        session,
                        ConversationState::ProfessionalRequests(state.clone()),
                        requests::reply(
                            &self.localizer,
                            session.locale,
                            &state,
                            &context.connections,
                            None,
                        ),
                        SessionTerminalStatus::Completed,
                        "open_professional_requests",
                    )
                }
            }
            Some("more.account") => self.same_state(
                context,
                session,
                Some(&subscription_message(
                    &self.localizer,
                    session.locale,
                    &context.billing,
                )),
                ConversationDisposition::Applied,
            ),
            _ => self.same_state(
                context,
                session,
                Some(
                    self.localizer
                        .text(session.locale, MessageKey::INPUT_UNKNOWN_BODY),
                ),
                ConversationDisposition::Unexpected,
            ),
        })
    }

    fn help(
        &self,
        context: &ConversationContext,
        input: &UserInput,
    ) -> Result<TurnPlan, EngineError> {
        let session = context.session.as_ref().ok_or(EngineError::InvalidState)?;
        if action(input) == Some("help.report") {
            let state = TrustState::List;
            return Ok(self.replace(
                context,
                session,
                ConversationState::Trust(state.clone()),
                trust::reply(
                    &self.localizer,
                    session.locale,
                    &state,
                    &context.trust,
                    None,
                ),
                SessionTerminalStatus::Completed,
                "open_report_flow",
            ));
        }
        let message = match action(input) {
            Some("help.about") => MessageKey::HELP_ABOUT_BODY,
            Some("help.emergency") => MessageKey::HELP_EMERGENCY_BODY,
            _ => MessageKey::INPUT_UNKNOWN_BODY,
        };
        Ok(self.same_state(
            context,
            session,
            Some(self.localizer.text(session.locale, message)),
            if message == MessageKey::INPUT_UNKNOWN_BODY {
                ConversationDisposition::Unexpected
            } else {
                ConversationDisposition::Applied
            },
        ))
    }

    fn global_plan(&self, context: &ConversationContext, command: GlobalCommand) -> TurnPlan {
        let Some(session) = &context.session else {
            return self.new_session_plan(context);
        };
        if context.confirmed_locale.is_none() {
            return match &session.state {
                ConversationState::LocaleChoose => {
                    self.same_state(context, session, None, ConversationDisposition::Applied)
                }
                ConversationState::LocaleConfirm { .. } => TurnPlan {
                    session_change: SessionChange::Advance {
                        session_id: session.id,
                        expected_version: session.version,
                        next: ConversationState::LocaleChoose,
                    },
                    locale_change: None,
                    business_command: None,
                    reply: language_selection(&self.localizer, None),
                    disposition: ConversationDisposition::Applied,
                },
                ConversationState::MainShow
                | ConversationState::MoreShow
                | ConversationState::HelpShow
                | ConversationState::Professional(_)
                | ConversationState::Administrator(_)
                | ConversationState::Availability(_)
                | ConversationState::Discovery(_)
                | ConversationState::ProfessionalRequests(_)
                | ConversationState::Trust(_)
                | ConversationState::SafetyAdministrator(_) => {
                    self.same_state(context, session, None, ConversationDisposition::Unexpected)
                }
            };
        }
        match command {
            GlobalCommand::Menu => self.replace(
                context,
                session,
                ConversationState::MainShow,
                main_menu(&self.localizer, session.locale, None),
                SessionTerminalStatus::Abandoned,
                "menu_requested",
            ),
            GlobalCommand::Cancel => {
                let prefix = if session.state == ConversationState::MainShow {
                    MessageKey::CANCEL_NONE_BODY
                } else {
                    MessageKey::CANCEL_DONE_BODY
                };
                self.replace(
                    context,
                    session,
                    ConversationState::MainShow,
                    main_menu(
                        &self.localizer,
                        session.locale,
                        Some(self.localizer.text(session.locale, prefix)),
                    ),
                    SessionTerminalStatus::Abandoned,
                    "canceled",
                )
            }
            GlobalCommand::Back => match &session.state {
                ConversationState::LocaleConfirm { .. } => self.replace(
                    context,
                    session,
                    ConversationState::LocaleChoose,
                    language_selection(&self.localizer, None),
                    SessionTerminalStatus::Abandoned,
                    "back",
                ),
                ConversationState::MoreShow
                | ConversationState::HelpShow
                | ConversationState::Professional(_)
                | ConversationState::Administrator(_)
                | ConversationState::Discovery(_)
                | ConversationState::ProfessionalRequests(_)
                | ConversationState::Trust(_)
                | ConversationState::SafetyAdministrator(_)
                | ConversationState::Availability(AvailabilityState::Status { .. })
                | ConversationState::Availability(AvailabilityState::Changed { .. }) => self
                    .replace(
                        context,
                        session,
                        ConversationState::MainShow,
                        main_menu(&self.localizer, session.locale, None),
                        SessionTerminalStatus::Abandoned,
                        "back",
                    ),
                ConversationState::Availability(
                    AvailabilityState::ChooseDuration { .. }
                    | AvailabilityState::ConfirmStop { .. },
                ) => availability::back_to_status(&self.localizer, context, session),
                ConversationState::MainShow => self.same_state(
                    context,
                    session,
                    Some(
                        self.localizer
                            .text(session.locale, MessageKey::NAV_BACK_AT_ROOT_BODY),
                    ),
                    ConversationDisposition::Applied,
                ),
                ConversationState::LocaleChoose => {
                    self.same_state(context, session, None, ConversationDisposition::Applied)
                }
            },
        }
    }

    fn same_state(
        &self,
        context: &ConversationContext,
        session: &crate::SessionSnapshot,
        prefix: Option<&str>,
        disposition: ConversationDisposition,
    ) -> TurnPlan {
        TurnPlan {
            session_change: SessionChange::Advance {
                session_id: session.id,
                expected_version: session.version,
                next: session.state.clone(),
            },
            locale_change: None,
            business_command: None,
            reply: self.render_state(context, &session.state, session.locale, prefix),
            disposition,
        }
    }

    #[allow(clippy::unused_self)]
    fn replace(
        &self,
        _context: &ConversationContext,
        session: &crate::SessionSnapshot,
        next: ConversationState,
        reply: ReplySpec,
        terminal_status: SessionTerminalStatus,
        terminal_reason: &'static str,
    ) -> TurnPlan {
        TurnPlan {
            session_change: SessionChange::Replace {
                session_id: session.id,
                expected_version: session.version,
                next,
                locale: session.locale,
                terminal_status,
                terminal_reason,
            },
            locale_change: None,
            business_command: None,
            reply,
            disposition: ConversationDisposition::Applied,
        }
    }

    fn render_state(
        &self,
        context: &ConversationContext,
        state: &ConversationState,
        locale: Locale,
        prefix: Option<&str>,
    ) -> ReplySpec {
        match state {
            ConversationState::LocaleChoose => language_selection(&self.localizer, prefix),
            ConversationState::LocaleConfirm { candidate } => {
                language_confirmation(&self.localizer, *candidate, prefix)
            }
            ConversationState::MainShow => main_menu(&self.localizer, locale, prefix),
            ConversationState::MoreShow => more_menu(
                &self.localizer,
                locale,
                matches!(context.administrator, AdminView::Allowed(_)),
                !matches!(
                    context.availability,
                    AvailabilityView::Ineligible(
                        AvailabilityIneligibility::ProfessionalRoleRequired
                    )
                ),
                !matches!(
                    context.availability,
                    AvailabilityView::Ineligible(
                        AvailabilityIneligibility::ProfessionalRoleRequired
                    )
                ),
                prefix,
            ),
            ConversationState::HelpShow => help_menu(&self.localizer, locale, prefix),
            ConversationState::Professional(state) => professional_reply(
                &self.localizer,
                locale,
                state,
                &context.professional,
                prefix,
            ),
            ConversationState::Administrator(state) => administrator_reply(
                &self.localizer,
                locale,
                state,
                &context.administrator,
                prefix,
            ),
            ConversationState::Availability(state) => {
                availability::reply(&self.localizer, locale, state, context.availability, prefix)
            }
            ConversationState::Discovery(state) => discovery::reply(
                &self.localizer,
                locale,
                state,
                &context.discovery,
                &context.connections,
                prefix,
            ),
            ConversationState::ProfessionalRequests(state) => {
                requests::reply(&self.localizer, locale, state, &context.connections, prefix)
            }
            ConversationState::Trust(state) => {
                trust::reply(&self.localizer, locale, state, &context.trust, prefix)
            }
            ConversationState::SafetyAdministrator(state) => safety_admin::reply(
                &self.localizer,
                locale,
                state,
                &context.safety_administrator,
                prefix,
            ),
        }
    }
}

fn validate_rendered_catalogs(localizer: &Localizer) -> Result<(), EngineError> {
    use crate::{
        AdminQueueItem, AllowedAdminView, AvailabilityDuration, AvailabilityEpochView,
        AvailabilityLocalExpiry, AvailabilityOutcome, AvailabilityState, AvailabilityView,
        CategorySelection, ContactMode, ContactSessionLimit, IdentityCheckStatus, LocalServiceMode,
        OpaqueTargetToken, ProfessionalFlowMode, ProfessionalStatus, ProfessionalSummary,
        ProfilePhotoStatus, ServiceCategory, ServiceContactPreference, ServiceRadius, ServiceSkill,
    };

    let summary = ProfessionalSummary {
        display_name: "Sample Professional".to_owned(),
        categories: CategorySelection::new(true, true),
        skills: vec![ServiceSkill::LeakRepair, ServiceSkill::HomeWiring],
        local_mode: LocalServiceMode::Both,
        radius: ServiceRadius::Km10,
        service_languages: Locale::ALL.to_vec(),
        contact_preferences: vec![
            ServiceContactPreference {
                category: ServiceCategory::Plumber,
                mode: ContactMode::Direct,
            },
            ServiceContactPreference {
                category: ServiceCategory::Electrician,
                mode: ContactMode::ApprovalRequired,
            },
        ],
        contact_session_limit: ContactSessionLimit::Five,
        photo: ProfilePhotoStatus::Present,
        identity_check: IdentityCheckStatus::Checked,
    };
    let token = OpaqueTargetToken::parse("catalog-token").map_err(|_| EngineError::InvalidState)?;
    let admin = AdminView::Allowed(AllowedAdminView {
        pending: vec![AdminQueueItem {
            target: token.clone(),
            version: 1,
            summary: summary.clone(),
        }],
        selected: Some(AdminQueueItem {
            target: token.clone(),
            version: 1,
            summary: summary.clone(),
        }),
    });
    for locale in Locale::ALL {
        let professional_view = crate::ProfessionalView {
            status: ProfessionalStatus::Approved,
            version: Some(1),
            summary: Some(summary.clone()),
            ..crate::ProfessionalView::default()
        };
        let mut replies = vec![
            language_selection(localizer, None),
            language_confirmation(
                localizer,
                locale,
                Some(localizer.text(locale, MessageKey::SELECTION_STALE_BODY)),
            ),
            main_menu(
                localizer,
                locale,
                Some(localizer.text(locale, MessageKey::SESSION_EXPIRED_BODY)),
            ),
            more_menu(
                localizer,
                locale,
                true,
                true,
                true,
                Some(localizer.text(locale, MessageKey::INPUT_UNKNOWN_BODY)),
            ),
            help_menu(
                localizer,
                locale,
                Some(localizer.text(locale, MessageKey::HELP_EMERGENCY_BODY)),
            ),
        ];
        let categories = CategorySelection::new(true, true);
        let professional_states = vec![
            ProfessionalState::DisplayNameInput {
                mode: ProfessionalFlowMode::Initial,
            },
            ProfessionalState::DisplayNameConfirm {
                mode: ProfessionalFlowMode::Initial,
            },
            ProfessionalState::Categories {
                mode: ProfessionalFlowMode::Initial,
                selected: categories,
            },
            ProfessionalState::Skills {
                mode: ProfessionalFlowMode::Initial,
                categories,
                category: ServiceCategory::Plumber,
                selected: vec![ServiceSkill::LeakRepair],
            },
            ProfessionalState::Skills {
                mode: ProfessionalFlowMode::Initial,
                categories,
                category: ServiceCategory::Electrician,
                selected: vec![ServiceSkill::HomeWiring],
            },
            ProfessionalState::ServiceArea {
                mode: ProfessionalFlowMode::Initial,
                categories,
            },
            ProfessionalState::Location {
                mode: ProfessionalFlowMode::Initial,
                categories,
            },
            ProfessionalState::Radius {
                mode: ProfessionalFlowMode::Initial,
                categories,
            },
            ProfessionalState::Languages {
                mode: ProfessionalFlowMode::Initial,
                categories,
                selected: Locale::ALL.to_vec(),
            },
            ProfessionalState::ContactMode {
                mode: ProfessionalFlowMode::Initial,
                categories,
                category: ServiceCategory::Plumber,
            },
            ProfessionalState::ContactMode {
                mode: ProfessionalFlowMode::Initial,
                categories,
                category: ServiceCategory::Electrician,
            },
            ProfessionalState::ContactLimit {
                mode: ProfessionalFlowMode::Initial,
            },
            ProfessionalState::Photo {
                mode: ProfessionalFlowMode::Initial,
            },
            ProfessionalState::Disclosure {
                mode: ProfessionalFlowMode::Initial,
            },
            ProfessionalState::Consent {
                mode: ProfessionalFlowMode::Initial,
                version: crate::PROFESSIONAL_CONSENT_VERSION,
                document_set_digest: Some([7; 32]),
            },
            ProfessionalState::Summary {
                mode: ProfessionalFlowMode::Initial,
            },
            ProfessionalState::Status,
            ProfessionalState::EditMenu,
        ];
        replies.extend(
            professional_states.iter().map(|state| {
                professional_reply(localizer, locale, state, &professional_view, None)
            }),
        );
        let admin_states = [
            AdminState::Queue { page: 0 },
            AdminState::Inspect {
                target: token.clone(),
                target_version: 1,
            },
            AdminState::Reason {
                target: token.clone(),
                target_version: 1,
                decision: crate::AdminReviewDecision::ChangesRequested,
            },
            AdminState::Confirm {
                target: token.clone(),
                target_version: 1,
                decision: crate::AdminReviewDecision::Approve,
                reason: None,
            },
            AdminState::Confirm {
                target: token.clone(),
                target_version: 1,
                decision: crate::AdminReviewDecision::Reject,
                reason: Some(crate::ReviewReasonCode::PolicyViolation),
            },
        ];
        replies.extend(
            admin_states
                .iter()
                .map(|state| administrator_reply(localizer, locale, state, &admin, None)),
        );
        replies.push(administrator_reply(
            localizer,
            locale,
            &AdminState::Queue { page: 0 },
            &AdminView::Denied,
            None,
        ));
        let availability_epoch = AvailabilityEpochView {
            generation: 1,
            version: 1,
            local_expiry: AvailabilityLocalExpiry {
                year: 2026,
                month: 12,
                day: 31,
                hour: 23,
                minute: 59,
            },
            contacts_used: 4,
            contact_limit: 10,
            successor: Some(AvailabilityDuration::FourHours),
        };
        for view in [
            AvailabilityView::Unavailable,
            AvailabilityView::Available(availability_epoch),
            AvailabilityView::Stopped(availability_epoch),
            AvailabilityView::CapacityPaused(availability_epoch),
            AvailabilityView::Expired(availability_epoch),
        ] {
            replies.push(availability::reply(
                localizer,
                locale,
                &AvailabilityState::Status {
                    observation: view.observation(),
                },
                view,
                None,
            ));
        }
        replies.push(availability::reply(
            localizer,
            locale,
            &AvailabilityState::Changed {
                outcome: AvailabilityOutcome::RenewalScheduled(AvailabilityDuration::EndOfLocalDay),
            },
            AvailabilityView::Available(availability_epoch),
            None,
        ));
        for reply in replies {
            validate_reply(&reply)?;
        }
    }
    Ok(())
}

fn validate_reply(reply: &ReplySpec) -> Result<(), EngineError> {
    let body_length = reply.body.encode_utf16().count();
    let valid = match &reply.controls {
        crate::ReplyControls::None => body_length <= 4_096,
        crate::ReplyControls::Buttons(buttons) => {
            body_length <= 1_024
                && (1..=3).contains(&buttons.len())
                && buttons.iter().all(|button| {
                    !button.id.is_empty()
                        && button.id.len() <= 256
                        && !button.title.is_empty()
                        && button.title.encode_utf16().count() <= 20
                })
        }
        crate::ReplyControls::List {
            open_title,
            section_title,
            rows,
        } => {
            body_length <= 1_024
                && !open_title.is_empty()
                && open_title.encode_utf16().count() <= 20
                && !section_title.is_empty()
                && section_title.encode_utf16().count() <= 24
                && (1..=10).contains(&rows.len())
                && rows.iter().all(|row| {
                    !row.id.is_empty()
                        && row.id.len() <= 200
                        && !row.title.is_empty()
                        && row.title.encode_utf16().count() <= 24
                        && row.description.as_ref().is_none_or(|description| {
                            !description.is_empty() && description.encode_utf16().count() <= 72
                        })
                })
        }
    };
    if valid {
        Ok(())
    } else {
        Err(EngineError::InvalidRenderedCatalog)
    }
}

#[derive(Clone, Copy)]
enum GlobalCommand {
    Back,
    Cancel,
    Menu,
}

fn global_command(input: &UserInput) -> Option<GlobalCommand> {
    match input {
        UserInput::Text(text) => match text.command() {
            "/back" | "back" | "वापस" | "पीछे" | "मागे" => {
                Some(GlobalCommand::Back)
            }
            "/cancel" | "cancel" | "रद्द" | "रद्द करें" | "रद्द करा" => {
                Some(GlobalCommand::Cancel)
            }
            "/menu" | "menu" | "मेन्यू" | "मेनू" => Some(GlobalCommand::Menu),
            _ => None,
        },
        UserInput::Action { id, .. } => match id.as_str() {
            "nav.back" => Some(GlobalCommand::Back),
            "nav.cancel" => Some(GlobalCommand::Cancel),
            "nav.menu" => Some(GlobalCommand::Menu),
            _ => None,
        },
        UserInput::Location | UserInput::Media | UserInput::Unsupported => None,
    }
}

fn action(input: &UserInput) -> Option<&str> {
    match input {
        UserInput::Action { id, .. } => Some(id.as_str()),
        _ => None,
    }
}

fn locale_from_action(action: &str) -> Option<Locale> {
    match action {
        "locale.en" => Some(Locale::EnIn),
        "locale.hi" => Some(Locale::HiIn),
        "locale.mr" => Some(Locale::MrIn),
        _ => None,
    }
}

fn typed_locale(input: &UserInput) -> Option<Locale> {
    let UserInput::Text(text) = input else {
        return None;
    };
    match text.command() {
        "english" => Some(Locale::EnIn),
        "हिंदी" | "hindi" => Some(Locale::HiIn),
        "मराठी" | "marathi" => Some(Locale::MrIn),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::ConversationEngine;
    use crate::{
        ActionId, AdminQueueItem, AdminReviewDecision, AdminState, AdminView, AllowedAdminView,
        AvailabilityCommand, AvailabilityDuration, AvailabilityEpochView, AvailabilityLocalExpiry,
        AvailabilityObservationState, AvailabilityOutcome, AvailabilityState, AvailabilityView,
        BusinessCommand, CategorySelection, ContactMode, ContactSessionLimit, ConversationContext,
        ConversationDisposition, ConversationState, DiscoveryState, IdentityCheckStatus,
        LocalServiceMode, NormalizedText, OpaqueTargetToken, ProfessionalCommand,
        ProfessionalFlowMode, ProfessionalResumeStep, ProfessionalState, ProfessionalStatus,
        ProfessionalSummary, ProfessionalView, ProfilePhotoStatus, ReviewReasonCode,
        ServiceCategory, ServiceContactPreference, ServiceRadius, ServiceSkill, SessionChange,
        SessionSnapshot, SessionTerminalStatus, UserInput,
    };
    use sahayak_domain::{ConversationSessionId, CorrelationId, OutboundMessageId};
    use sahayak_localization::Locale;

    fn session(state: ConversationState, locale: Locale) -> SessionSnapshot {
        SessionSnapshot {
            id: ConversationSessionId::new(),
            state,
            locale,
            version: 1,
            expected_reply_to: Some(OutboundMessageId::new()),
            workflow_correlation_id: CorrelationId::new(),
        }
    }

    fn context(state: ConversationState) -> ConversationContext {
        ConversationContext {
            confirmed_locale: Some(Locale::EnIn),
            session: Some(session(state, Locale::EnIn)),
            session_expired: false,
            professional: ProfessionalView::default(),
            administrator: AdminView::Denied,
            availability: AvailabilityView::default(),
            discovery: crate::DiscoveryView::default(),
            connections: crate::ConnectionsView::default(),
            billing: crate::BillingView::FreeValue,
            trust: crate::TrustView::default(),
            safety_administrator: crate::SafetyAdminView::Denied,
        }
    }

    fn action_for(context: &ConversationContext, id: &str) -> Result<UserInput, crate::InputError> {
        let reply_to = context
            .session
            .as_ref()
            .and_then(|session| session.expected_reply_to);
        Ok(UserInput::Action {
            id: ActionId::parse(id)?,
            reply_to,
        })
    }

    fn advance_context(context: &mut ConversationContext, plan: &crate::TurnPlan) {
        let next = match &plan.session_change {
            crate::SessionChange::Create { next, .. }
            | crate::SessionChange::Advance { next, .. }
            | crate::SessionChange::Replace { next, .. } => next.clone(),
        };
        if let Some(session) = context.session.as_mut() {
            session.state = next;
            session.version += 1;
        }
        if matches!(
            plan.business_command,
            Some(BusinessCommand::Professional(
                ProfessionalCommand::AcceptConsent { .. }
            ))
        ) {
            context.professional.accepted_consent_version =
                Some(crate::PROFESSIONAL_CONSENT_VERSION);
        }
    }

    fn summary() -> ProfessionalSummary {
        ProfessionalSummary {
            display_name: "Ravi Services".to_owned(),
            categories: CategorySelection::new(true, true),
            skills: vec![ServiceSkill::LeakRepair, ServiceSkill::HomeWiring],
            local_mode: LocalServiceMode::Both,
            radius: ServiceRadius::Km10,
            service_languages: vec![Locale::EnIn, Locale::HiIn],
            contact_preferences: vec![
                ServiceContactPreference {
                    category: ServiceCategory::Plumber,
                    mode: ContactMode::Direct,
                },
                ServiceContactPreference {
                    category: ServiceCategory::Electrician,
                    mode: ContactMode::ApprovalRequired,
                },
            ],
            contact_session_limit: ContactSessionLimit::Three,
            photo: ProfilePhotoStatus::Present,
            identity_check: IdentityCheckStatus::NotChecked,
        }
    }

    #[test]
    fn new_user_must_choose_and_confirm_language() -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let first = engine.decide(
            &ConversationContext {
                confirmed_locale: None,
                session: None,
                session_expired: false,
                professional: ProfessionalView::default(),
                administrator: AdminView::Denied,
                availability: AvailabilityView::default(),
                discovery: crate::DiscoveryView::default(),
                connections: crate::ConnectionsView::default(),
                billing: crate::BillingView::FreeValue,
                trust: crate::TrustView::default(),
                safety_administrator: crate::SafetyAdminView::Denied,
            },
            &UserInput::Unsupported,
        )?;
        assert!(matches!(
            first.session_change,
            crate::SessionChange::Create {
                next: ConversationState::LocaleChoose,
                ..
            }
        ));

        let prompt = OutboundMessageId::new();
        let mut current = session(ConversationState::LocaleChoose, Locale::EnIn);
        current.expected_reply_to = Some(prompt);
        let selected = engine.decide(
            &ConversationContext {
                confirmed_locale: None,
                session: Some(current),
                session_expired: false,
                professional: ProfessionalView::default(),
                administrator: AdminView::Denied,
                availability: AvailabilityView::default(),
                discovery: crate::DiscoveryView::default(),
                connections: crate::ConnectionsView::default(),
                billing: crate::BillingView::FreeValue,
                trust: crate::TrustView::default(),
                safety_administrator: crate::SafetyAdminView::Denied,
            },
            &UserInput::Action {
                id: ActionId::parse("locale.hi")?,
                reply_to: Some(prompt),
            },
        )?;
        assert!(matches!(
            selected.session_change,
            crate::SessionChange::Advance {
                next: ConversationState::LocaleConfirm {
                    candidate: Locale::HiIn
                },
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn locale_confirmation_has_one_typed_command_and_compatibility_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let mut context = context(ConversationState::LocaleConfirm {
            candidate: Locale::HiIn,
        });
        context.confirmed_locale = None;
        let plan = engine.decide(&context, &action_for(&context, "locale.confirm")?)?;
        assert_eq!(plan.locale_change, Some(Locale::HiIn));
        assert!(matches!(
            plan.business_command,
            Some(BusinessCommand::Account(crate::AccountCommand::SetLocale {
                locale: Locale::HiIn
            }))
        ));
        assert!(matches!(
            plan.session_change,
            crate::SessionChange::Replace {
                terminal_status: SessionTerminalStatus::Completed,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn complete_basic_onboarding_emits_markers_and_both_contact_modes()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let mut context = context(ConversationState::MainShow);
        let mut plan = engine.decide(&context, &action_for(&context, "main.offer")?)?;
        advance_context(&mut context, &plan);

        plan = engine.decide(
            &context,
            &UserInput::Text(NormalizedText::parse("Ravi Services")?),
        )?;
        assert!(matches!(
            plan.business_command,
            Some(BusinessCommand::Professional(
                ProfessionalCommand::StageDisplayName { .. }
            ))
        ));
        advance_context(&mut context, &plan);

        for id in [
            "pro.name.confirm",
            "pro.category.plumber",
            "pro.category.electrician",
            "pro.category.done",
            "pro.skill.leak",
            "pro.skill.done",
            "pro.skill.wiring",
            "pro.skill.done",
            "pro.area.both",
        ] {
            plan = engine.decide(&context, &action_for(&context, id)?)?;
            advance_context(&mut context, &plan);
        }
        plan = engine.decide(&context, &action_for(&context, "pro.radius.10")?)?;
        assert_eq!(
            plan.business_command,
            Some(BusinessCommand::Professional(
                ProfessionalCommand::SetRadius {
                    radius: ServiceRadius::Km10
                }
            ))
        );
        advance_context(&mut context, &plan);
        plan = engine.decide(&context, &UserInput::Location)?;
        assert_eq!(
            plan.business_command,
            Some(BusinessCommand::Professional(
                ProfessionalCommand::CurrentInboundLocation
            ))
        );
        advance_context(&mut context, &plan);

        for id in [
            "pro.language.en",
            "pro.language.hi",
            "pro.language.done",
            "pro.contact.direct",
            "pro.contact.approval",
            "pro.limit.3",
        ] {
            plan = engine.decide(&context, &action_for(&context, id)?)?;
            advance_context(&mut context, &plan);
        }
        plan = engine.decide(&context, &UserInput::Media)?;
        assert_eq!(
            plan.business_command,
            Some(BusinessCommand::Professional(
                ProfessionalCommand::CurrentInboundMedia
            ))
        );
        advance_context(&mut context, &plan);

        for id in [
            "pro.disclosure.continue",
            "pro.summary.submit",
            "pro.consent.accept",
            "pro.summary.submit",
        ] {
            plan = engine.decide(&context, &action_for(&context, id)?)?;
            advance_context(&mut context, &plan);
        }
        assert!(matches!(
            plan.business_command,
            Some(BusinessCommand::Professional(
                ProfessionalCommand::SubmitForReview { edited: false, .. }
            ))
        ));
        assert!(matches!(
            context.session.as_ref().map(|session| &session.state),
            Some(ConversationState::Professional(ProfessionalState::Status))
        ));
        Ok(())
    }

    #[test]
    fn unexpected_input_and_stale_actions_do_not_emit_business_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let context = context(ConversationState::Professional(
            ProfessionalState::Location {
                mode: ProfessionalFlowMode::Initial,
                categories: CategorySelection::new(true, false),
            },
        ));
        let unexpected = engine.decide(&context, &UserInput::Unsupported)?;
        assert_eq!(
            unexpected.disposition,
            crate::ConversationDisposition::Unexpected
        );
        assert!(unexpected.business_command.is_none());
        let stale = engine.decide(
            &context,
            &UserInput::Action {
                id: ActionId::parse("pro.radius.5")?,
                reply_to: Some(OutboundMessageId::new()),
            },
        )?;
        assert_eq!(stale.disposition, crate::ConversationDisposition::Stale);
        assert!(stale.business_command.is_none());
        Ok(())
    }

    #[test]
    fn cancel_and_menu_abandon_professional_flow() -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        for command in ["/cancel", "/menu"] {
            let context = context(ConversationState::Professional(ProfessionalState::Photo {
                mode: ProfessionalFlowMode::Initial,
            }));
            let plan =
                engine.decide(&context, &UserInput::Text(NormalizedText::parse(command)?))?;
            assert!(matches!(
                plan.session_change,
                crate::SessionChange::Replace {
                    next: ConversationState::MainShow,
                    ..
                }
            ));
            assert!(plan.business_command.is_none());
        }
        Ok(())
    }

    #[test]
    fn offer_resumes_changes_and_shows_approved_status() -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let mut changes = context(ConversationState::MainShow);
        changes.professional = ProfessionalView {
            status: ProfessionalStatus::ChangesRequested,
            version: Some(4),
            summary: Some(summary()),
            resume_step: Some(ProfessionalResumeStep::Photo),
            ..ProfessionalView::default()
        };
        let status = engine.decide(&changes, &action_for(&changes, "main.offer")?)?;
        advance_context(&mut changes, &status);
        let resumed = engine.decide(&changes, &action_for(&changes, "pro.status.resume")?)?;
        assert!(matches!(
            resumed.session_change,
            crate::SessionChange::Advance {
                next: ConversationState::Professional(ProfessionalState::Photo {
                    mode: ProfessionalFlowMode::Edit
                }),
                ..
            }
        ));

        let mut approved = context(ConversationState::MainShow);
        approved.professional.status = ProfessionalStatus::Approved;
        approved.professional.summary = Some(summary());
        let plan = engine.decide(&approved, &action_for(&approved, "main.offer")?)?;
        assert!(plan.reply.body.contains("approved"));
        Ok(())
    }

    #[test]
    fn returning_professional_sees_review_outcome_after_reentry()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let context = ConversationContext {
            confirmed_locale: Some(Locale::EnIn),
            session: None,
            session_expired: true,
            professional: ProfessionalView {
                status: ProfessionalStatus::Approved,
                summary: Some(summary()),
                ..ProfessionalView::default()
            },
            administrator: AdminView::Denied,
            availability: AvailabilityView::default(),
            discovery: crate::DiscoveryView::default(),
            connections: crate::ConnectionsView::default(),
            billing: crate::BillingView::FreeValue,
            trust: crate::TrustView::default(),
            safety_administrator: crate::SafetyAdminView::Denied,
        };
        let plan = engine.decide(&context, &UserInput::Unsupported)?;
        assert!(plan.reply.body.contains("approved"));
        assert!(matches!(
            plan.session_change,
            crate::SessionChange::Create {
                next: ConversationState::Professional(ProfessionalState::Status),
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn availability_start_stop_renew_and_stale_paths_are_typed()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let mut context = context(ConversationState::MoreShow);
        let role_denied = engine.decide(&context, &action_for(&context, "more.availability")?)?;
        assert!(role_denied.business_command.is_none());
        assert!(matches!(
            role_denied.session_change,
            SessionChange::Advance { .. }
        ));
        context.availability =
            AvailabilityView::Ineligible(crate::AvailabilityIneligibility::ProfileApprovalRequired);
        let denied = engine.decide(&context, &action_for(&context, "more.availability")?)?;
        assert!(denied.business_command.is_none());
        assert!(matches!(
            denied.session_change,
            SessionChange::Replace {
                next: ConversationState::Availability(AvailabilityState::Status { .. }),
                ..
            }
        ));
        context.availability = AvailabilityView::Unavailable;
        context.session = Some(session(ConversationState::MoreShow, Locale::EnIn));
        let mut plan = engine.decide(&context, &action_for(&context, "more.availability")?)?;
        advance_context(&mut context, &plan);
        plan = engine.decide(&context, &action_for(&context, "availability.set")?)?;
        advance_context(&mut context, &plan);
        plan = engine.decide(
            &context,
            &action_for(&context, "availability.duration.one_hour")?,
        )?;
        assert_eq!(
            plan.business_command,
            Some(BusinessCommand::Availability(AvailabilityCommand::Start {
                duration: AvailabilityDuration::OneHour,
                expected: context.availability.observation(),
            }))
        );
        for (action, duration) in [
            (
                "availability.duration.four_hours",
                AvailabilityDuration::FourHours,
            ),
            (
                "availability.duration.end_of_day",
                AvailabilityDuration::EndOfLocalDay,
            ),
        ] {
            let selection = engine.decide(&context, &action_for(&context, action)?)?;
            assert_eq!(
                selection.business_command,
                Some(BusinessCommand::Availability(AvailabilityCommand::Start {
                    duration,
                    expected: context.availability.observation(),
                }))
            );
        }

        let epoch = AvailabilityEpochView {
            generation: 4,
            version: 7,
            local_expiry: AvailabilityLocalExpiry {
                year: 2026,
                month: 8,
                day: 31,
                hour: 18,
                minute: 30,
            },
            contacts_used: 1,
            contact_limit: 3,
            successor: None,
        };
        context.availability = AvailabilityView::Available(epoch);
        context.session = Some(session(
            ConversationState::Availability(AvailabilityState::Status {
                observation: context.availability.observation(),
            }),
            Locale::EnIn,
        ));
        plan = engine.decide(&context, &action_for(&context, "availability.stop")?)?;
        advance_context(&mut context, &plan);
        plan = engine.decide(
            &context,
            &action_for(&context, "availability.stop.confirm")?,
        )?;
        assert!(matches!(
            plan.business_command,
            Some(BusinessCommand::Availability(
                AvailabilityCommand::Stop { .. }
            ))
        ));

        let stale_observation = crate::AvailabilityObservation {
            state: AvailabilityObservationState::Available,
            generation: Some(3),
            version: Some(6),
        };
        context.session = Some(session(
            ConversationState::Availability(AvailabilityState::Status {
                observation: stale_observation,
            }),
            Locale::EnIn,
        ));
        plan = engine.decide(&context, &UserInput::Unsupported)?;
        assert_eq!(plan.disposition, ConversationDisposition::Stale);
        assert!(plan.business_command.is_none());

        context.availability = AvailabilityView::CapacityPaused(AvailabilityEpochView {
            contacts_used: 3,
            contact_limit: 3,
            ..epoch
        });
        context.session = Some(session(
            ConversationState::Availability(AvailabilityState::Status {
                observation: context.availability.observation(),
            }),
            Locale::EnIn,
        ));
        plan = engine.decide(&context, &action_for(&context, "availability.resume")?)?;
        assert!(plan.business_command.is_none());
        Ok(())
    }

    #[test]
    fn customer_discovery_cards_and_professional_requests_are_privacy_safe()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let mut context = context(ConversationState::MainShow);
        let mut plan = engine.decide(&context, &action_for(&context, "main.find")?)?;
        advance_context(&mut context, &plan);
        plan = engine.decide(
            &context,
            &action_for(&context, "discovery.category.plumber")?,
        )?;
        assert!(matches!(
            plan.business_command,
            Some(BusinessCommand::Discovery(crate::DiscoveryCommand::Begin {
                category: ServiceCategory::Plumber
            }))
        ));

        context.discovery = crate::DiscoveryView {
            status: crate::DiscoveryStatus::Results,
            request_token: Some("11111111-1111-4111-8111-111111111111".to_owned()),
            version: Some(4),
            category: Some(ServiceCategory::Plumber),
            radius_km: Some(5),
            has_more: true,
            cards: vec![crate::DiscoveryCardView {
                candidate_token: "22222222-2222-4222-8222-222222222222".to_owned(),
                display_name: "Ravi".to_owned(),
                public_reference: "33333333-3333-4333-8333-333333333333".to_owned(),
                category: ServiceCategory::Plumber,
                distance_label: "under_1_km".to_owned(),
                language_compatible: true,
                availability_label: "recently_confirmed".to_owned(),
                identity_checked: false,
                contact_mode: ContactMode::Direct,
            }],
        };
        context.session = Some(session(
            ConversationState::Discovery(DiscoveryState::Results {
                request_token: "11111111-1111-4111-8111-111111111111".to_owned(),
            }),
            Locale::EnIn,
        ));
        let rendered = engine.decide(&context, &UserInput::Unsupported)?;
        assert!(!rendered.reply.body.contains("+91"));
        let more = engine.decide(&context, &action_for(&context, "discovery.show_more")?)?;
        assert!(matches!(
            more.business_command,
            Some(BusinessCommand::Discovery(
                crate::DiscoveryCommand::ShowMore { .. }
            ))
        ));
        plan = engine.decide(
            &context,
            &action_for(
                &context,
                "discovery.select:22222222-2222-4222-8222-222222222222",
            )?,
        )?;
        assert!(plan.business_command.is_none());

        context.discovery.status = crate::DiscoveryStatus::NoResults;
        context.discovery.cards.clear();
        let expanded = engine.decide(&context, &action_for(&context, "discovery.expand")?)?;
        assert!(matches!(
            expanded.business_command,
            Some(BusinessCommand::Discovery(
                crate::DiscoveryCommand::ExpandRadius { .. }
            ))
        ));

        context
            .connections
            .pending
            .push(crate::PendingConnectionView {
                request_token: "44444444-4444-4444-8444-444444444444".to_owned(),
                version: 1,
                category: ServiceCategory::Plumber,
                issue_code: "leak_repair".to_owned(),
                requested_time: "now".to_owned(),
                distance_label: "under_1_km".to_owned(),
            });
        context.session = None;
        let pending = engine.decide(&context, &UserInput::Unsupported)?;
        assert!(matches!(
            pending.session_change,
            SessionChange::Create {
                next: ConversationState::ProfessionalRequests(
                    crate::ProfessionalRequestsState::List
                ),
                ..
            }
        ));
        assert!(!pending.reply.body.contains("customer phone"));
        context.session = Some(session(
            ConversationState::ProfessionalRequests(crate::ProfessionalRequestsState::List),
            Locale::EnIn,
        ));
        plan = engine.decide(
            &context,
            &action_for(
                &context,
                "request.select:44444444-4444-4444-8444-444444444444",
            )?,
        )?;
        advance_context(&mut context, &plan);
        plan = engine.decide(&context, &action_for(&context, "request.decline")?)?;
        advance_context(&mut context, &plan);
        plan = engine.decide(&context, &action_for(&context, "request.confirm")?)?;
        assert!(matches!(
            plan.business_command,
            Some(BusinessCommand::Connection(
                crate::ConnectionCommand::Respond { accept: false, .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn denied_administrator_entry_is_localized_and_has_no_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let context = context(ConversationState::MoreShow);
        let plan = engine.decide(&context, &action_for(&context, "more.admin")?)?;
        assert!(plan.reply.body.contains("not authorized"));
        assert!(plan.business_command.is_none());
        assert_eq!(plan.disposition, crate::ConversationDisposition::Unexpected);
        Ok(())
    }

    #[test]
    fn subscription_status_menu_is_account_wide_and_localized()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let mut context = context(ConversationState::MoreShow);
        context.billing = crate::BillingView::PaymentRequired {
            hosted_payment_url: Some("https://rzp.io/i/test-payment".to_owned()),
        };
        let plan = engine.decide(&context, &action_for(&context, "more.account")?)?;
        assert!(plan.reply.body.contains("INR 99"));
        assert!(plan.reply.body.contains("https://rzp.io/i/test-payment"));
        assert!(plan.business_command.is_none());
        Ok(())
    }

    #[test]
    fn qualified_introduction_supports_review_and_report_flows()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let token = "11111111-1111-4111-8111-111111111111";
        let mut context = context(ConversationState::MoreShow);
        context
            .trust
            .introductions
            .push(crate::TrustIntroductionView {
                reveal_token: token.to_owned(),
                counterpart_label: Some("Ravi".to_owned()),
                category_code: "plumber".to_owned(),
                current_account_is_customer: true,
                already_reviewed: false,
                already_reported: false,
                already_blocked: false,
            });
        let mut plan = engine.decide(&context, &action_for(&context, "more.trust")?)?;
        advance_context(&mut context, &plan);
        for action in [
            format!("trust.select:{token}"),
            "trust.review".to_owned(),
            "trust.rating:5".to_owned(),
            "trust.rating:4".to_owned(),
            "trust.rating:5".to_owned(),
            "trust.feedback.skip".to_owned(),
        ] {
            plan = engine.decide(&context, &action_for(&context, &action)?)?;
            advance_context(&mut context, &plan);
        }
        assert!(matches!(
            plan.business_command,
            Some(BusinessCommand::Trust(
                crate::TrustCommand::SubmitReview { .. }
            ))
        ));

        context.session = Some(session(
            ConversationState::Trust(crate::TrustState::List),
            Locale::EnIn,
        ));
        for action in [
            format!("trust.select:{token}"),
            "trust.report".to_owned(),
            "trust.category:fraud".to_owned(),
            "trust.report.block".to_owned(),
            "trust.description.skip".to_owned(),
        ] {
            plan = engine.decide(&context, &action_for(&context, &action)?)?;
            advance_context(&mut context, &plan);
        }
        assert!(matches!(
            plan.business_command,
            Some(BusinessCommand::Trust(crate::TrustCommand::SubmitReport {
                block_subject: true,
                ..
            }))
        ));
        Ok(())
    }

    #[test]
    fn administrator_safety_flow_requires_confirmation() -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let token = "66666666-6666-4666-8666-666666666666";
        let mut context = context(ConversationState::MoreShow);
        context.safety_administrator = crate::SafetyAdminView::Allowed {
            reports: vec![crate::SafetyAdminReportView {
                report_token: token.to_owned(),
                version: 2,
                category: "fraud".to_owned(),
                severity: "high".to_owned(),
            }],
        };
        let mut plan = engine.decide(&context, &action_for(&context, "more.safety_admin")?)?;
        advance_context(&mut context, &plan);
        for action in [
            format!("safety.admin.select:{token}"),
            "safety.admin.action:warning".to_owned(),
        ] {
            plan = engine.decide(&context, &action_for(&context, &action)?)?;
            advance_context(&mut context, &plan);
        }
        assert!(plan.business_command.is_none());
        plan = engine.decide(&context, &action_for(&context, "safety.admin.confirm")?)?;
        assert!(matches!(
            plan.business_command,
            Some(BusinessCommand::SafetyModeration(
                crate::SafetyModerationCommand {
                    expected_version: 2,
                    ..
                }
            ))
        ));
        Ok(())
    }

    #[test]
    fn administrator_review_uses_index_and_requires_confirmation()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        let token = OpaqueTargetToken::parse("opaque-review-token")?;
        let item = AdminQueueItem {
            target: token.clone(),
            version: 7,
            summary: summary(),
        };
        let mut context = context(ConversationState::MoreShow);
        context.administrator = AdminView::Allowed(AllowedAdminView {
            pending: vec![item.clone()],
            selected: Some(item),
        });
        let mut plan = engine.decide(&context, &action_for(&context, "more.admin")?)?;
        advance_context(&mut context, &plan);
        let select_action = format!("admin.queue.select:{}", token.as_str());
        plan = engine.decide(&context, &action_for(&context, &select_action)?)?;
        advance_context(&mut context, &plan);
        plan = engine.decide(&context, &action_for(&context, "admin.decision.changes")?)?;
        advance_context(&mut context, &plan);
        plan = engine.decide(&context, &action_for(&context, "admin.reason.incomplete")?)?;
        advance_context(&mut context, &plan);
        assert!(plan.business_command.is_none());
        plan = engine.decide(&context, &action_for(&context, "admin.confirm.yes")?)?;
        assert_eq!(
            plan.business_command,
            Some(BusinessCommand::Administrator(
                crate::AdminCommand::ReviewProfile {
                    target: token,
                    expected_version: 7,
                    decision: AdminReviewDecision::ChangesRequested,
                    reason: Some(ReviewReasonCode::IncompleteDetails),
                }
            ))
        );
        Ok(())
    }

    #[test]
    fn catalogs_render_every_new_flow_in_all_locales() -> Result<(), Box<dyn std::error::Error>> {
        let engine = ConversationEngine::load()?;
        for locale in Locale::ALL {
            let mut context = context(ConversationState::Professional(
                ProfessionalState::Disclosure {
                    mode: ProfessionalFlowMode::Initial,
                },
            ));
            if let Some(session) = context.session.as_mut() {
                session.locale = locale;
            }
            let plan = engine.decide(&context, &UserInput::Unsupported)?;
            assert!(!plan.reply.body.is_empty());
        }
        Ok(())
    }

    #[test]
    fn all_session_states_round_trip_without_sensitive_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let token = OpaqueTargetToken::parse("round-trip-token")?;
        let availability_observation = crate::AvailabilityObservation {
            state: AvailabilityObservationState::Available,
            generation: Some(7),
            version: Some(3),
        };
        let states = vec![
            ConversationState::LocaleChoose,
            ConversationState::LocaleConfirm {
                candidate: Locale::MrIn,
            },
            ConversationState::MainShow,
            ConversationState::MoreShow,
            ConversationState::HelpShow,
            ConversationState::Professional(ProfessionalState::DisplayNameConfirm {
                mode: ProfessionalFlowMode::Initial,
            }),
            ConversationState::Professional(ProfessionalState::Skills {
                mode: ProfessionalFlowMode::Initial,
                categories: CategorySelection::new(true, true),
                category: ServiceCategory::Plumber,
                selected: vec![ServiceSkill::LeakRepair],
            }),
            ConversationState::Professional(ProfessionalState::Consent {
                mode: ProfessionalFlowMode::Edit,
                version: 1,
                document_set_digest: Some([9; 32]),
            }),
            ConversationState::Administrator(AdminState::Queue { page: 3 }),
            ConversationState::Administrator(AdminState::Confirm {
                target: token,
                target_version: 9,
                decision: AdminReviewDecision::Reject,
                reason: Some(ReviewReasonCode::PolicyViolation),
            }),
            ConversationState::Availability(AvailabilityState::Status {
                observation: availability_observation,
            }),
            ConversationState::Availability(AvailabilityState::ChooseDuration {
                observation: availability_observation,
                intent: crate::AvailabilityIntent::Renew,
            }),
            ConversationState::Availability(AvailabilityState::ConfirmStop {
                observation: availability_observation,
            }),
            ConversationState::Availability(AvailabilityState::Changed {
                outcome: AvailabilityOutcome::RenewalScheduled(AvailabilityDuration::FourHours),
            }),
            ConversationState::Discovery(DiscoveryState::ConfirmSelection {
                request_token: "11111111-1111-4111-8111-111111111111".to_owned(),
                request_version: 4,
                candidate_token: "22222222-2222-4222-8222-222222222222".to_owned(),
                contact_mode: ContactMode::Direct,
            }),
            ConversationState::ProfessionalRequests(crate::ProfessionalRequestsState::Confirm {
                request_token: "33333333-3333-4333-8333-333333333333".to_owned(),
                version: 2,
                accept: true,
            }),
            ConversationState::Trust(crate::TrustState::ReviewFeedback {
                reveal_token: "44444444-4444-4444-8444-444444444444".to_owned(),
                connection: 5,
                responsiveness: 4,
                completion: 5,
            }),
            ConversationState::Trust(crate::TrustState::ReportDescription {
                reveal_token: "55555555-5555-4555-8555-555555555555".to_owned(),
                category: "fraud".to_owned(),
                block_subject: true,
            }),
            ConversationState::SafetyAdministrator(crate::SafetyAdminState::Confirm {
                report_token: "77777777-7777-4777-8777-777777777777".to_owned(),
                version: 3,
                action: crate::SafetyAdminAction::TemporarySuspension,
            }),
        ];
        for state in states {
            let data = state.data();
            let serialized = serde_json::to_string(&data)?;
            assert!(!serialized.contains("Ravi"));
            assert!(!serialized.contains("coordinate"));
            let decoded = ConversationState::from_persisted(
                state.workflow().key(),
                state.workflow().version(),
                state.key(),
                &data,
            );
            assert_eq!(decoded, Some(state));
        }
        Ok(())
    }

    #[test]
    fn normalized_text_debug_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let text = NormalizedText::parse("Private Name")?;
        assert_eq!(format!("{text:?}"), "NormalizedText([REDACTED])");
        Ok(())
    }
}
