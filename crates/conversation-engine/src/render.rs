use crate::{
    AdminReviewDecision, AdminState, AdminView, ButtonSpec, CategorySelection, ContactMode,
    IdentityCheckStatus, ListRowSpec, LocalServiceMode, ProfessionalState, ProfessionalStatus,
    ProfessionalSummary, ProfessionalView, ProfileFieldCode, ProfilePhotoStatus, ReplyControls,
    ReplySpec, ReviewReasonCode, ServiceCategory, ServiceSkill,
};
use sahayak_localization::{Locale, Localizer, MessageKey};

pub(crate) const ADMIN_PAGE_SIZE: usize = 7;

pub(crate) fn language_selection(localizer: &Localizer, prefix: Option<&str>) -> ReplySpec {
    let body = join(
        prefix,
        &[
            localizer.text(Locale::EnIn, MessageKey::LANGUAGE_SELECT_BODY),
            localizer.text(Locale::HiIn, MessageKey::LANGUAGE_SELECT_BODY),
            localizer.text(Locale::MrIn, MessageKey::LANGUAGE_SELECT_BODY),
        ]
        .join("\n"),
    );
    ReplySpec {
        body,
        controls: ReplyControls::Buttons(vec![
            button(
                "locale.en",
                localizer.text(Locale::EnIn, MessageKey::LANGUAGE_OPTION_EN),
            ),
            button(
                "locale.hi",
                localizer.text(Locale::HiIn, MessageKey::LANGUAGE_OPTION_HI),
            ),
            button(
                "locale.mr",
                localizer.text(Locale::MrIn, MessageKey::LANGUAGE_OPTION_MR),
            ),
        ]),
    }
}

pub(crate) fn language_confirmation(
    localizer: &Localizer,
    locale: Locale,
    prefix: Option<&str>,
) -> ReplySpec {
    ReplySpec {
        body: join(
            prefix,
            localizer.text(locale, MessageKey::LANGUAGE_CONFIRM_BODY),
        ),
        controls: ReplyControls::Buttons(vec![
            button(
                "locale.confirm",
                localizer.text(locale, MessageKey::LANGUAGE_CONFIRM_YES),
            ),
            button(
                "locale.change",
                localizer.text(locale, MessageKey::LANGUAGE_CONFIRM_CHANGE),
            ),
        ]),
    }
}

pub(crate) fn main_menu(localizer: &Localizer, locale: Locale, prefix: Option<&str>) -> ReplySpec {
    ReplySpec {
        body: join(prefix, localizer.text(locale, MessageKey::MAIN_BODY)),
        controls: ReplyControls::Buttons(vec![
            button("main.find", localizer.text(locale, MessageKey::MAIN_FIND)),
            button("main.offer", localizer.text(locale, MessageKey::MAIN_OFFER)),
            button("main.more", localizer.text(locale, MessageKey::MAIN_MORE)),
        ]),
    }
}

pub(crate) fn more_menu(
    localizer: &Localizer,
    locale: Locale,
    admin_allowed: bool,
    availability_allowed: bool,
    requests_allowed: bool,
    prefix: Option<&str>,
) -> ReplySpec {
    let mut rows = Vec::with_capacity(7);
    if availability_allowed {
        rows.push(row(
            localizer,
            locale,
            "more.availability",
            MessageKey::MORE_AVAILABILITY_TITLE,
            Some(MessageKey::MORE_AVAILABILITY_DESC),
        ));
    }
    if requests_allowed {
        rows.push(row(
            localizer,
            locale,
            "more.requests",
            MessageKey::MORE_REQUESTS_TITLE,
            Some(MessageKey::MORE_REQUESTS_DESC),
        ));
    }
    rows.extend([
        row(
            localizer,
            locale,
            "more.trust",
            MessageKey::TRUST_LIST_TITLE,
            Some(MessageKey::HELP_REPORT_DESC),
        ),
        row(
            localizer,
            locale,
            "more.contacts",
            MessageKey::MORE_CONTACTS_TITLE,
            Some(MessageKey::MORE_CONTACTS_DESC),
        ),
        row(
            localizer,
            locale,
            "more.account",
            MessageKey::MORE_ACCOUNT_TITLE,
            Some(MessageKey::MORE_ACCOUNT_DESC),
        ),
        row(
            localizer,
            locale,
            "more.help",
            MessageKey::MORE_HELP_TITLE,
            Some(MessageKey::MORE_HELP_DESC),
        ),
        row(
            localizer,
            locale,
            "more.language",
            MessageKey::MORE_LANGUAGE_TITLE,
            Some(MessageKey::MORE_LANGUAGE_DESC),
        ),
    ]);
    if admin_allowed {
        rows.push(row(
            localizer,
            locale,
            "more.safety_admin",
            MessageKey::SAFETY_ADMIN_QUEUE_TITLE,
            Some(MessageKey::HELP_REPORT_DESC),
        ));
        rows.push(row(
            localizer,
            locale,
            "more.admin",
            MessageKey::MORE_ADMIN_TITLE,
            Some(MessageKey::MORE_ADMIN_DESC),
        ));
    }
    ReplySpec {
        body: join(prefix, localizer.text(locale, MessageKey::MORE_BODY)),
        controls: ReplyControls::List {
            open_title: localizer.text(locale, MessageKey::MORE_OPEN).to_owned(),
            section_title: localizer.text(locale, MessageKey::MORE_BODY).to_owned(),
            rows,
        },
    }
}

pub(crate) fn help_menu(localizer: &Localizer, locale: Locale, prefix: Option<&str>) -> ReplySpec {
    ReplySpec {
        body: join(prefix, localizer.text(locale, MessageKey::HELP_MENU_BODY)),
        controls: ReplyControls::List {
            open_title: localizer
                .text(locale, MessageKey::HELP_MENU_OPEN)
                .to_owned(),
            section_title: localizer
                .text(locale, MessageKey::HELP_MENU_OPEN)
                .to_owned(),
            rows: vec![
                row(
                    localizer,
                    locale,
                    "help.about",
                    MessageKey::HELP_ABOUT_TITLE,
                    Some(MessageKey::HELP_ABOUT_DESC),
                ),
                row(
                    localizer,
                    locale,
                    "help.report",
                    MessageKey::HELP_REPORT_TITLE,
                    Some(MessageKey::HELP_REPORT_DESC),
                ),
                row(
                    localizer,
                    locale,
                    "help.emergency",
                    MessageKey::HELP_EMERGENCY_TITLE,
                    Some(MessageKey::HELP_EMERGENCY_DESC),
                ),
                row(localizer, locale, "nav.back", MessageKey::NAV_BACK, None),
            ],
        },
    }
}

pub(crate) fn professional_reply(
    localizer: &Localizer,
    locale: Locale,
    state: &ProfessionalState,
    view: &ProfessionalView,
    prefix: Option<&str>,
) -> ReplySpec {
    let mut reply = match state {
        ProfessionalState::DisplayNameInput { .. } => text_reply(
            localizer.text(locale, MessageKey::PRO_NAME_BODY),
            ReplyControls::None,
        ),
        ProfessionalState::DisplayNameConfirm { .. } => text_reply(
            localizer.text(locale, MessageKey::PRO_NAME_CONFIRM_BODY),
            ReplyControls::Buttons(vec![
                button(
                    "pro.name.confirm",
                    localizer.text(locale, MessageKey::PRO_NAME_USE_TITLE),
                ),
                button(
                    "pro.name.change",
                    localizer.text(locale, MessageKey::PRO_NAME_CHANGE_TITLE),
                ),
            ]),
        ),
        ProfessionalState::Categories { selected, .. } => {
            let body = selection_body(
                localizer,
                locale,
                MessageKey::PRO_CATEGORIES_BODY,
                MessageKey::PRO_SUMMARY_CATEGORIES_LABEL,
                category_names(localizer, locale, *selected),
            );
            text_reply(
                &body,
                ReplyControls::Buttons(vec![
                    button(
                        "pro.category.plumber",
                        localizer.text(locale, MessageKey::PRO_CATEGORY_PLUMBER_TITLE),
                    ),
                    button(
                        "pro.category.electrician",
                        localizer.text(locale, MessageKey::PRO_CATEGORY_ELECTRICIAN_TITLE),
                    ),
                    button(
                        "pro.category.done",
                        localizer.text(locale, MessageKey::PRO_SELECTION_DONE_TITLE),
                    ),
                ]),
            )
        }
        ProfessionalState::Skills {
            category, selected, ..
        } => skills_reply(localizer, locale, *category, selected),
        ProfessionalState::ServiceArea { .. } => text_reply(
            localizer.text(locale, MessageKey::PRO_AREA_BODY),
            ReplyControls::Buttons(vec![
                button(
                    "pro.area.travel",
                    localizer.text(locale, MessageKey::PRO_AREA_TRAVEL_TITLE),
                ),
                button(
                    "pro.area.visits",
                    localizer.text(locale, MessageKey::PRO_AREA_VISITS_TITLE),
                ),
                button(
                    "pro.area.both",
                    localizer.text(locale, MessageKey::PRO_AREA_BOTH_TITLE),
                ),
            ]),
        ),
        ProfessionalState::Location { .. } => text_reply(
            localizer.text(locale, MessageKey::PRO_LOCATION_BODY),
            ReplyControls::None,
        ),
        ProfessionalState::Radius { .. } => list_reply(
            localizer.text(locale, MessageKey::PRO_RADIUS_BODY),
            localizer.text(locale, MessageKey::PRO_RADIUS_OPEN_TITLE),
            localizer.text(locale, MessageKey::PRO_RADIUS_OPEN_TITLE),
            vec![
                row(
                    localizer,
                    locale,
                    "pro.radius.2",
                    MessageKey::PRO_RADIUS_2_TITLE,
                    None,
                ),
                row(
                    localizer,
                    locale,
                    "pro.radius.5",
                    MessageKey::PRO_RADIUS_5_TITLE,
                    None,
                ),
                row(
                    localizer,
                    locale,
                    "pro.radius.10",
                    MessageKey::PRO_RADIUS_10_TITLE,
                    None,
                ),
                row(
                    localizer,
                    locale,
                    "pro.radius.25",
                    MessageKey::PRO_RADIUS_25_TITLE,
                    None,
                ),
            ],
        ),
        ProfessionalState::Languages { selected, .. } => {
            let names = selected
                .iter()
                .map(|selected_locale| locale_name(localizer, locale, *selected_locale))
                .collect();
            let body = selection_body(
                localizer,
                locale,
                MessageKey::PRO_LANGUAGES_BODY,
                MessageKey::PRO_SUMMARY_LANGUAGES_LABEL,
                names,
            );
            list_reply(
                &body,
                localizer.text(locale, MessageKey::PRO_LANGUAGES_OPEN_TITLE),
                localizer.text(locale, MessageKey::PRO_LANGUAGES_OPEN_TITLE),
                vec![
                    row(
                        localizer,
                        locale,
                        "pro.language.en",
                        MessageKey::LANGUAGE_OPTION_EN,
                        None,
                    ),
                    row(
                        localizer,
                        locale,
                        "pro.language.hi",
                        MessageKey::LANGUAGE_OPTION_HI,
                        None,
                    ),
                    row(
                        localizer,
                        locale,
                        "pro.language.mr",
                        MessageKey::LANGUAGE_OPTION_MR,
                        None,
                    ),
                    row(
                        localizer,
                        locale,
                        "pro.language.done",
                        MessageKey::PRO_SELECTION_DONE_TITLE,
                        None,
                    ),
                ],
            )
        }
        ProfessionalState::ContactMode { category, .. } => {
            let body = match category {
                ServiceCategory::Plumber => MessageKey::PRO_CONTACT_PLUMBER_BODY,
                ServiceCategory::Electrician => MessageKey::PRO_CONTACT_ELECTRICIAN_BODY,
            };
            text_reply(
                localizer.text(locale, body),
                ReplyControls::Buttons(vec![
                    button(
                        "pro.contact.direct",
                        localizer.text(locale, MessageKey::PRO_CONTACT_DIRECT_TITLE),
                    ),
                    button(
                        "pro.contact.approval",
                        localizer.text(locale, MessageKey::PRO_CONTACT_APPROVAL_TITLE),
                    ),
                ]),
            )
        }
        ProfessionalState::ContactLimit { .. } => list_reply(
            localizer.text(locale, MessageKey::PRO_LIMIT_BODY),
            localizer.text(locale, MessageKey::PRO_LIMIT_OPEN_TITLE),
            localizer.text(locale, MessageKey::PRO_LIMIT_OPEN_TITLE),
            vec![
                row(
                    localizer,
                    locale,
                    "pro.limit.1",
                    MessageKey::PRO_LIMIT_1_TITLE,
                    None,
                ),
                row(
                    localizer,
                    locale,
                    "pro.limit.3",
                    MessageKey::PRO_LIMIT_3_TITLE,
                    None,
                ),
                row(
                    localizer,
                    locale,
                    "pro.limit.5",
                    MessageKey::PRO_LIMIT_5_TITLE,
                    None,
                ),
                row(
                    localizer,
                    locale,
                    "pro.limit.10",
                    MessageKey::PRO_LIMIT_10_TITLE,
                    None,
                ),
            ],
        ),
        ProfessionalState::Photo { .. } => text_reply(
            localizer.text(locale, MessageKey::PRO_PHOTO_BODY),
            ReplyControls::Buttons(vec![
                button(
                    "pro.photo.skip",
                    localizer.text(locale, MessageKey::PRO_PHOTO_SKIP_TITLE),
                ),
                button(
                    "pro.photo.remove",
                    localizer.text(locale, MessageKey::PRO_PHOTO_REMOVE_TITLE),
                ),
            ]),
        ),
        ProfessionalState::Disclosure { .. } => text_reply(
            localizer.text(locale, MessageKey::PRO_DISCLOSURE_BODY),
            ReplyControls::Buttons(vec![
                button(
                    "pro.disclosure.continue",
                    localizer.text(locale, MessageKey::PRO_CONTINUE_TITLE),
                ),
                button("nav.cancel", localizer.text(locale, MessageKey::NAV_CANCEL)),
            ]),
        ),
        ProfessionalState::Consent { .. } => text_reply(
            localizer.text(locale, MessageKey::PRO_CONSENT_BODY),
            ReplyControls::Buttons(vec![
                button(
                    "pro.consent.accept",
                    localizer.text(locale, MessageKey::PRO_CONSENT_ACCEPT_TITLE),
                ),
                button("nav.cancel", localizer.text(locale, MessageKey::NAV_CANCEL)),
            ]),
        ),
        ProfessionalState::Summary { .. } => summary_reply(localizer, locale, view),
        ProfessionalState::Status => status_reply(localizer, locale, view),
        ProfessionalState::EditMenu => edit_menu(localizer, locale),
    };
    reply.body = join(prefix, &reply.body);
    reply
}

pub(crate) fn administrator_reply(
    localizer: &Localizer,
    locale: Locale,
    state: &AdminState,
    view: &AdminView,
    prefix: Option<&str>,
) -> ReplySpec {
    let AdminView::Allowed(allowed) = view else {
        return text_reply(
            &join(
                prefix,
                localizer.text(locale, MessageKey::ADMIN_DENIED_BODY),
            ),
            ReplyControls::Buttons(vec![button(
                "nav.menu",
                localizer.text(locale, MessageKey::NAV_MAIN),
            )]),
        );
    };
    let mut reply = match state {
        AdminState::Queue { page } => admin_queue(localizer, locale, allowed, *page),
        AdminState::Inspect {
            target,
            target_version,
        } => selected_admin_item(allowed, target, *target_version).map_or_else(
            || admin_queue(localizer, locale, allowed, 0),
            |item| {
                let body = format!(
                    "{}\n\n{}",
                    localizer.text(locale, MessageKey::ADMIN_INSPECT_BODY),
                    summary_text(localizer, locale, &item.summary)
                );
                text_reply(
                    &body,
                    ReplyControls::Buttons(vec![
                        button(
                            "admin.decision.approve",
                            localizer.text(locale, MessageKey::ADMIN_APPROVE_TITLE),
                        ),
                        button(
                            "admin.decision.changes",
                            localizer.text(locale, MessageKey::ADMIN_CHANGES_TITLE),
                        ),
                        button(
                            "admin.decision.reject",
                            localizer.text(locale, MessageKey::ADMIN_REJECT_TITLE),
                        ),
                    ]),
                )
            },
        ),
        AdminState::Reason { .. } => list_reply(
            localizer.text(locale, MessageKey::ADMIN_REASON_BODY),
            localizer.text(locale, MessageKey::ADMIN_REASON_OPEN_TITLE),
            localizer.text(locale, MessageKey::ADMIN_REASON_OPEN_TITLE),
            vec![
                row(
                    localizer,
                    locale,
                    "admin.reason.incomplete",
                    MessageKey::ADMIN_REASON_INCOMPLETE_TITLE,
                    Some(MessageKey::ADMIN_REASON_INCOMPLETE_DESC),
                ),
                row(
                    localizer,
                    locale,
                    "admin.reason.mismatch",
                    MessageKey::ADMIN_REASON_MISMATCH_TITLE,
                    Some(MessageKey::ADMIN_REASON_MISMATCH_DESC),
                ),
                row(
                    localizer,
                    locale,
                    "admin.reason.photo",
                    MessageKey::ADMIN_REASON_PHOTO_TITLE,
                    Some(MessageKey::ADMIN_REASON_PHOTO_DESC),
                ),
                row(
                    localizer,
                    locale,
                    "admin.reason.policy",
                    MessageKey::ADMIN_REASON_POLICY_TITLE,
                    Some(MessageKey::ADMIN_REASON_POLICY_DESC),
                ),
                row(localizer, locale, "nav.back", MessageKey::NAV_BACK, None),
            ],
        ),
        AdminState::Confirm { decision, .. } => {
            let body = match decision {
                AdminReviewDecision::Approve => MessageKey::ADMIN_CONFIRM_APPROVE_BODY,
                AdminReviewDecision::ChangesRequested => MessageKey::ADMIN_CONFIRM_CHANGES_BODY,
                AdminReviewDecision::Reject => MessageKey::ADMIN_CONFIRM_REJECT_BODY,
            };
            text_reply(
                localizer.text(locale, body),
                ReplyControls::Buttons(vec![
                    button(
                        "admin.confirm.yes",
                        localizer.text(locale, MessageKey::ADMIN_CONFIRM_YES_TITLE),
                    ),
                    button(
                        "admin.confirm.no",
                        localizer.text(locale, MessageKey::ADMIN_CONFIRM_NO_TITLE),
                    ),
                ]),
            )
        }
    };
    reply.body = join(prefix, &reply.body);
    reply
}

pub(crate) fn summary_text(
    localizer: &Localizer,
    locale: Locale,
    summary: &ProfessionalSummary,
) -> String {
    let categories = category_names(localizer, locale, summary.categories).join(", ");
    let skills = summary
        .skills
        .iter()
        .map(|skill| skill_name(localizer, locale, *skill))
        .collect::<Vec<_>>()
        .join(", ");
    let languages = summary
        .service_languages
        .iter()
        .map(|language| locale_name(localizer, locale, *language))
        .collect::<Vec<_>>()
        .join(", ");
    let contacts = summary
        .contact_preferences
        .iter()
        .map(|preference| {
            format!(
                "{}: {}",
                category_name(localizer, locale, preference.category),
                contact_name(localizer, locale, preference.mode)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let none = localizer.text(locale, MessageKey::PRO_VALUE_NONE);
    [
        format!(
            "{}: {}",
            localizer.text(locale, MessageKey::PRO_SUMMARY_DISPLAY_LABEL),
            truncate_utf16(&summary.display_name, 80)
        ),
        format!(
            "{}: {}",
            localizer.text(locale, MessageKey::PRO_SUMMARY_CATEGORIES_LABEL),
            if categories.is_empty() {
                none
            } else {
                &categories
            }
        ),
        format!(
            "{}: {}",
            localizer.text(locale, MessageKey::PRO_SUMMARY_SKILLS_LABEL),
            if skills.is_empty() { none } else { &skills }
        ),
        format!(
            "{}: {}",
            localizer.text(locale, MessageKey::PRO_SUMMARY_AREA_LABEL),
            area_name(localizer, locale, summary.local_mode)
        ),
        format!(
            "{}: {} km",
            localizer.text(locale, MessageKey::PRO_SUMMARY_RADIUS_LABEL),
            summary.radius.kilometres()
        ),
        format!(
            "{}: {}",
            localizer.text(locale, MessageKey::PRO_SUMMARY_LANGUAGES_LABEL),
            if languages.is_empty() {
                none
            } else {
                &languages
            }
        ),
        format!(
            "{}: {}",
            localizer.text(locale, MessageKey::PRO_SUMMARY_CONTACT_LABEL),
            if contacts.is_empty() { none } else { &contacts }
        ),
        format!(
            "{}: {}",
            localizer.text(locale, MessageKey::PRO_SUMMARY_LIMIT_LABEL),
            summary.contact_session_limit.value()
        ),
        format!(
            "{}: {}",
            localizer.text(locale, MessageKey::PRO_SUMMARY_PHOTO_LABEL),
            match summary.photo {
                ProfilePhotoStatus::None => {
                    localizer.text(locale, MessageKey::PRO_VALUE_PHOTO_NONE)
                }
                ProfilePhotoStatus::Present => {
                    localizer.text(locale, MessageKey::PRO_VALUE_PHOTO_PRESENT)
                }
            }
        ),
        format!(
            "{}: {}",
            localizer.text(locale, MessageKey::PRO_SUMMARY_IDENTITY_LABEL),
            match summary.identity_check {
                IdentityCheckStatus::NotChecked => {
                    localizer.text(locale, MessageKey::PRO_VALUE_IDENTITY_NOT_CHECKED)
                }
                IdentityCheckStatus::Checked => {
                    localizer.text(locale, MessageKey::PRO_VALUE_IDENTITY_CHECKED)
                }
            }
        ),
    ]
    .join("\n")
}

fn skills_reply(
    localizer: &Localizer,
    locale: Locale,
    category: ServiceCategory,
    selected: &[ServiceSkill],
) -> ReplySpec {
    let body_key = match category {
        ServiceCategory::Plumber => MessageKey::PRO_SKILLS_PLUMBER_BODY,
        ServiceCategory::Electrician => MessageKey::PRO_SKILLS_ELECTRICIAN_BODY,
    };
    let body = selection_body(
        localizer,
        locale,
        body_key,
        MessageKey::PRO_SUMMARY_SKILLS_LABEL,
        selected
            .iter()
            .map(|skill| skill_name(localizer, locale, *skill))
            .collect(),
    );
    let skill_rows = match category {
        ServiceCategory::Plumber => vec![
            ("pro.skill.leak", MessageKey::PRO_SKILL_LEAK_TITLE),
            ("pro.skill.fixture", MessageKey::PRO_SKILL_FIXTURE_TITLE),
            ("pro.skill.drain", MessageKey::PRO_SKILL_DRAIN_TITLE),
        ],
        ServiceCategory::Electrician => vec![
            ("pro.skill.wiring", MessageKey::PRO_SKILL_WIRING_TITLE),
            ("pro.skill.switch", MessageKey::PRO_SKILL_SWITCH_TITLE),
            ("pro.skill.fan", MessageKey::PRO_SKILL_FAN_TITLE),
        ],
    };
    let mut rows = skill_rows
        .into_iter()
        .map(|(id, key)| row(localizer, locale, id, key, None))
        .collect::<Vec<_>>();
    rows.push(row(
        localizer,
        locale,
        "pro.skill.done",
        MessageKey::PRO_SELECTION_DONE_TITLE,
        None,
    ));
    list_reply(
        &body,
        localizer.text(locale, MessageKey::PRO_SELECTION_DONE_TITLE),
        category_name(localizer, locale, category),
        rows,
    )
}

fn summary_reply(localizer: &Localizer, locale: Locale, view: &ProfessionalView) -> ReplySpec {
    let details = view.summary.as_ref().map_or_else(
        || {
            localizer
                .text(locale, MessageKey::PRO_VALUE_NONE)
                .to_owned()
        },
        |summary| summary_text(localizer, locale, summary),
    );
    let body = format!(
        "{}\n\n{}",
        localizer.text(locale, MessageKey::PRO_SUMMARY_BODY),
        details
    );
    let submit_title = if view.accepted_consent_version == Some(crate::PROFESSIONAL_CONSENT_VERSION)
    {
        MessageKey::PRO_SUMMARY_SUBMIT_TITLE
    } else {
        MessageKey::PRO_CONTINUE_TITLE
    };
    text_reply(
        &body,
        ReplyControls::Buttons(vec![
            button("pro.summary.submit", localizer.text(locale, submit_title)),
            button(
                "pro.summary.edit",
                localizer.text(locale, MessageKey::PRO_SUMMARY_EDIT_TITLE),
            ),
            button("nav.cancel", localizer.text(locale, MessageKey::NAV_CANCEL)),
        ]),
    )
}

fn status_reply(localizer: &Localizer, locale: Locale, view: &ProfessionalView) -> ReplySpec {
    let status_key = match view.status {
        ProfessionalStatus::NotStarted | ProfessionalStatus::Draft => {
            MessageKey::PRO_STATUS_DRAFT_BODY
        }
        ProfessionalStatus::PendingReview => MessageKey::PRO_STATUS_PENDING_BODY,
        ProfessionalStatus::ChangesRequested => MessageKey::PRO_STATUS_CHANGES_BODY,
        ProfessionalStatus::Approved => MessageKey::PRO_STATUS_APPROVED_BODY,
        ProfessionalStatus::Rejected => MessageKey::PRO_STATUS_REJECTED_BODY,
        ProfessionalStatus::Hidden => MessageKey::PRO_STATUS_HIDDEN_BODY,
    };
    let mut body = localizer.text(locale, status_key).to_owned();
    if !view.requested_changes.is_empty() {
        let fields = view
            .requested_changes
            .iter()
            .map(|field| field_name(localizer, locale, *field))
            .collect::<Vec<_>>()
            .join(", ");
        body.push('\n');
        body.push_str(&fields);
    }
    if let Some(reason) = view.review_reason {
        body.push('\n');
        body.push_str(reason_name(localizer, locale, reason));
    }
    let mut buttons = Vec::with_capacity(2);
    match view.status {
        ProfessionalStatus::NotStarted
        | ProfessionalStatus::Draft
        | ProfessionalStatus::ChangesRequested
        | ProfessionalStatus::Rejected
        | ProfessionalStatus::Hidden => buttons.push(button(
            "pro.status.resume",
            localizer.text(locale, MessageKey::PRO_STATUS_RESUME_TITLE),
        )),
        ProfessionalStatus::Approved => buttons.push(button(
            "pro.status.edit",
            localizer.text(locale, MessageKey::PRO_STATUS_EDIT_TITLE),
        )),
        ProfessionalStatus::PendingReview => {}
    }
    buttons.push(button(
        "nav.menu",
        localizer.text(locale, MessageKey::NAV_MAIN),
    ));
    text_reply(&body, ReplyControls::Buttons(buttons))
}

fn edit_menu(localizer: &Localizer, locale: Locale) -> ReplySpec {
    list_reply(
        localizer.text(locale, MessageKey::PRO_EDIT_BODY),
        localizer.text(locale, MessageKey::PRO_EDIT_OPEN_TITLE),
        localizer.text(locale, MessageKey::PRO_EDIT_OPEN_TITLE),
        vec![
            row(
                localizer,
                locale,
                "pro.edit.name",
                MessageKey::PRO_FIELD_DISPLAY_NAME_TITLE,
                None,
            ),
            row(
                localizer,
                locale,
                "pro.edit.services",
                MessageKey::PRO_FIELD_SERVICES_TITLE,
                None,
            ),
            row(
                localizer,
                locale,
                "pro.edit.area",
                MessageKey::PRO_FIELD_AREA_TITLE,
                None,
            ),
            row(
                localizer,
                locale,
                "pro.edit.languages",
                MessageKey::PRO_FIELD_LANGUAGES_TITLE,
                None,
            ),
            row(
                localizer,
                locale,
                "pro.edit.contact",
                MessageKey::PRO_FIELD_CONTACT_TITLE,
                None,
            ),
            row(
                localizer,
                locale,
                "pro.edit.photo",
                MessageKey::PRO_FIELD_PHOTO_TITLE,
                None,
            ),
            row(localizer, locale, "nav.back", MessageKey::NAV_BACK, None),
        ],
    )
}

fn admin_queue(
    localizer: &Localizer,
    locale: Locale,
    allowed: &crate::AllowedAdminView,
    page: u8,
) -> ReplySpec {
    let start = usize::from(page).saturating_mul(ADMIN_PAGE_SIZE);
    let items = allowed.pending.iter().skip(start).take(ADMIN_PAGE_SIZE);
    let mut rows = items
        .map(|item| ListRowSpec {
            id: format!("admin.queue.select:{}", item.target.as_str()),
            title: truncate_utf16(&item.summary.display_name, 24),
            description: Some(truncate_utf16(
                &category_names(localizer, locale, item.summary.categories).join(", "),
                72,
            )),
        })
        .collect::<Vec<_>>();
    if page > 0 {
        rows.push(row(
            localizer,
            locale,
            "admin.queue.previous",
            MessageKey::ADMIN_QUEUE_PREVIOUS_TITLE,
            None,
        ));
    }
    if start.saturating_add(ADMIN_PAGE_SIZE) < allowed.pending.len() {
        rows.push(row(
            localizer,
            locale,
            "admin.queue.next",
            MessageKey::ADMIN_QUEUE_NEXT_TITLE,
            None,
        ));
    }
    rows.push(row(
        localizer,
        locale,
        "nav.back",
        MessageKey::NAV_BACK,
        None,
    ));
    let body_key = if allowed.pending.get(start).is_some() {
        MessageKey::ADMIN_QUEUE_BODY
    } else {
        MessageKey::ADMIN_QUEUE_EMPTY_BODY
    };
    list_reply(
        localizer.text(locale, body_key),
        localizer.text(locale, MessageKey::ADMIN_QUEUE_OPEN_TITLE),
        localizer.text(locale, MessageKey::ADMIN_QUEUE_SECTION_TITLE),
        rows,
    )
}

fn selected_admin_item<'a>(
    allowed: &'a crate::AllowedAdminView,
    target: &crate::OpaqueTargetToken,
    version: i64,
) -> Option<&'a crate::AdminQueueItem> {
    allowed
        .selected
        .as_ref()
        .filter(|item| item.target == *target && item.version == version)
        .or_else(|| {
            allowed
                .pending
                .iter()
                .find(|item| item.target == *target && item.version == version)
        })
}

fn selection_body(
    localizer: &Localizer,
    locale: Locale,
    body_key: MessageKey,
    label_key: MessageKey,
    selected: Vec<&str>,
) -> String {
    let selected = if selected.is_empty() {
        localizer
            .text(locale, MessageKey::PRO_VALUE_NONE)
            .to_owned()
    } else {
        selected.join(", ")
    };
    format!(
        "{}\n{}: {}",
        localizer.text(locale, body_key),
        localizer.text(locale, label_key),
        selected
    )
}

fn category_names(localizer: &Localizer, locale: Locale, selected: CategorySelection) -> Vec<&str> {
    selected
        .values()
        .into_iter()
        .map(|category| category_name(localizer, locale, category))
        .collect()
}

fn category_name(localizer: &Localizer, locale: Locale, category: ServiceCategory) -> &str {
    localizer.text(
        locale,
        match category {
            ServiceCategory::Plumber => MessageKey::PRO_CATEGORY_PLUMBER_TITLE,
            ServiceCategory::Electrician => MessageKey::PRO_CATEGORY_ELECTRICIAN_TITLE,
        },
    )
}

fn skill_name(localizer: &Localizer, locale: Locale, skill: ServiceSkill) -> &str {
    localizer.text(
        locale,
        match skill {
            ServiceSkill::LeakRepair => MessageKey::PRO_SKILL_LEAK_TITLE,
            ServiceSkill::TapAndFixture => MessageKey::PRO_SKILL_FIXTURE_TITLE,
            ServiceSkill::DrainClearing => MessageKey::PRO_SKILL_DRAIN_TITLE,
            ServiceSkill::HomeWiring => MessageKey::PRO_SKILL_WIRING_TITLE,
            ServiceSkill::SwitchAndSocket => MessageKey::PRO_SKILL_SWITCH_TITLE,
            ServiceSkill::FanInstallation => MessageKey::PRO_SKILL_FAN_TITLE,
        },
    )
}

fn locale_name(localizer: &Localizer, display_locale: Locale, locale: Locale) -> &str {
    localizer.text(
        display_locale,
        match locale {
            Locale::EnIn => MessageKey::LANGUAGE_OPTION_EN,
            Locale::HiIn => MessageKey::LANGUAGE_OPTION_HI,
            Locale::MrIn => MessageKey::LANGUAGE_OPTION_MR,
        },
    )
}

fn contact_name(localizer: &Localizer, locale: Locale, mode: ContactMode) -> &str {
    localizer.text(
        locale,
        match mode {
            ContactMode::Direct => MessageKey::PRO_VALUE_CONTACT_DIRECT,
            ContactMode::ApprovalRequired => MessageKey::PRO_VALUE_CONTACT_APPROVAL,
        },
    )
}

fn area_name(localizer: &Localizer, locale: Locale, mode: LocalServiceMode) -> &str {
    localizer.text(
        locale,
        match mode {
            LocalServiceMode::TravelToCustomer => MessageKey::PRO_VALUE_AREA_TRAVEL,
            LocalServiceMode::CustomerVisits => MessageKey::PRO_VALUE_AREA_VISITS,
            LocalServiceMode::Both => MessageKey::PRO_VALUE_AREA_BOTH,
        },
    )
}

fn field_name(localizer: &Localizer, locale: Locale, field: ProfileFieldCode) -> &str {
    localizer.text(
        locale,
        match field {
            ProfileFieldCode::DisplayName => MessageKey::PRO_FIELD_DISPLAY_NAME_TITLE,
            ProfileFieldCode::Services => MessageKey::PRO_FIELD_SERVICES_TITLE,
            ProfileFieldCode::ServiceArea => MessageKey::PRO_FIELD_AREA_TITLE,
            ProfileFieldCode::Languages => MessageKey::PRO_FIELD_LANGUAGES_TITLE,
            ProfileFieldCode::Contact => MessageKey::PRO_FIELD_CONTACT_TITLE,
            ProfileFieldCode::Photo => MessageKey::PRO_FIELD_PHOTO_TITLE,
        },
    )
}

fn reason_name(localizer: &Localizer, locale: Locale, reason: ReviewReasonCode) -> &str {
    localizer.text(
        locale,
        match reason {
            ReviewReasonCode::IncompleteDetails => MessageKey::ADMIN_REASON_INCOMPLETE_TITLE,
            ReviewReasonCode::ServiceMismatch => MessageKey::ADMIN_REASON_MISMATCH_TITLE,
            ReviewReasonCode::PhotoConcern => MessageKey::ADMIN_REASON_PHOTO_TITLE,
            ReviewReasonCode::PolicyViolation => MessageKey::ADMIN_REASON_POLICY_TITLE,
        },
    )
}

pub(crate) fn button(id: impl Into<String>, title: &str) -> ButtonSpec {
    ButtonSpec {
        id: id.into(),
        title: title.to_owned(),
    }
}

fn row(
    localizer: &Localizer,
    locale: Locale,
    id: impl Into<String>,
    title: MessageKey,
    description: Option<MessageKey>,
) -> ListRowSpec {
    ListRowSpec {
        id: id.into(),
        title: localizer.text(locale, title).to_owned(),
        description: description.map(|key| localizer.text(locale, key).to_owned()),
    }
}

fn text_reply(body: &str, controls: ReplyControls) -> ReplySpec {
    ReplySpec {
        body: body.to_owned(),
        controls,
    }
}

fn list_reply(
    body: &str,
    open_title: &str,
    section_title: &str,
    rows: Vec<ListRowSpec>,
) -> ReplySpec {
    text_reply(
        body,
        ReplyControls::List {
            open_title: open_title.to_owned(),
            section_title: section_title.to_owned(),
            rows,
        },
    )
}

fn join(prefix: Option<&str>, body: &str) -> String {
    prefix.map_or_else(|| body.to_owned(), |prefix| format!("{prefix}\n\n{body}"))
}

fn truncate_utf16(value: &str, limit: usize) -> String {
    let mut units = 0;
    value
        .chars()
        .take_while(|character| {
            let next = units + character.len_utf16();
            if next > limit {
                false
            } else {
                units = next;
                true
            }
        })
        .collect()
}
