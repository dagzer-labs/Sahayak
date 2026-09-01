use crate::{
    BusinessCommand, ButtonSpec, ConversationContext, ConversationDisposition, ConversationState,
    ListRowSpec, ReplyControls, ReplySpec, SafetyAdminAction, SafetyAdminState, SafetyAdminView,
    SafetyModerationCommand, SessionChange, SessionSnapshot, TurnPlan, UserInput,
};
use sahayak_localization::{Locale, Localizer, MessageKey};

pub(crate) fn decide(
    localizer: &Localizer,
    context: &ConversationContext,
    state: &SafetyAdminState,
    input: &UserInput,
) -> TurnPlan {
    let Some(session) = context.session.as_ref() else {
        return invalid(localizer, context, state);
    };
    let SafetyAdminView::Allowed { reports } = &context.safety_administrator else {
        return invalid(localizer, context, state);
    };
    match state {
        SafetyAdminState::Queue => {
            if let Some(token) =
                action(input).and_then(|value| value.strip_prefix("safety.admin.select:"))
                && let Some(report) = reports.iter().find(|report| report.report_token == token)
            {
                return advance(
                    localizer,
                    context,
                    session,
                    SafetyAdminState::Inspect {
                        report_token: token.to_owned(),
                        version: report.version,
                    },
                    None,
                );
            }
            invalid(localizer, context, state)
        }
        SafetyAdminState::Inspect {
            report_token,
            version,
        } => {
            let selected = action(input)
                .and_then(|value| value.strip_prefix("safety.admin.action:"))
                .and_then(parse_action);
            selected.map_or_else(
                || invalid(localizer, context, state),
                |action| {
                    advance(
                        localizer,
                        context,
                        session,
                        SafetyAdminState::Confirm {
                            report_token: report_token.clone(),
                            version: *version,
                            action,
                        },
                        None,
                    )
                },
            )
        }
        SafetyAdminState::Confirm {
            report_token,
            version,
            action: selected,
        } => match action(input) {
            Some("safety.admin.confirm") => advance(
                localizer,
                context,
                session,
                SafetyAdminState::Done,
                Some(BusinessCommand::SafetyModeration(SafetyModerationCommand {
                    report_token: report_token.clone(),
                    expected_version: *version,
                    action: *selected,
                })),
            ),
            Some("safety.admin.cancel") => advance(
                localizer,
                context,
                session,
                SafetyAdminState::Inspect {
                    report_token: report_token.clone(),
                    version: *version,
                },
                None,
            ),
            _ => invalid(localizer, context, state),
        },
        SafetyAdminState::Done => match action(input) {
            Some("safety.admin.queue") => {
                advance(localizer, context, session, SafetyAdminState::Queue, None)
            }
            _ => invalid(localizer, context, state),
        },
    }
}

pub(crate) fn reply(
    localizer: &Localizer,
    locale: Locale,
    state: &SafetyAdminState,
    view: &SafetyAdminView,
    prefix: Option<&str>,
) -> ReplySpec {
    let mut reply = match state {
        SafetyAdminState::Queue => {
            let reports = match view {
                SafetyAdminView::Allowed { reports } => reports.as_slice(),
                SafetyAdminView::Denied => &[],
            };
            let rows: Vec<ListRowSpec> = reports
                .iter()
                .take(10)
                .map(|report| ListRowSpec {
                    id: format!("safety.admin.select:{}", report.report_token),
                    title: format!("{} · {}", report.severity, report.category),
                    description: None,
                })
                .collect();
            let controls = if rows.is_empty() {
                ReplyControls::None
            } else {
                ReplyControls::List {
                    open_title: localizer
                        .text(locale, MessageKey::SAFETY_ADMIN_QUEUE_TITLE)
                        .to_owned(),
                    section_title: localizer
                        .text(locale, MessageKey::SAFETY_ADMIN_QUEUE_TITLE)
                        .to_owned(),
                    rows,
                }
            };
            ReplySpec {
                body: localizer
                    .text(
                        locale,
                        if reports.is_empty() {
                            MessageKey::SAFETY_ADMIN_EMPTY_BODY
                        } else {
                            MessageKey::SAFETY_ADMIN_QUEUE_BODY
                        },
                    )
                    .to_owned(),
                controls,
            }
        }
        SafetyAdminState::Inspect { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::SAFETY_ADMIN_INSPECT_BODY)
                .to_owned(),
            controls: ReplyControls::List {
                open_title: localizer
                    .text(locale, MessageKey::SAFETY_ADMIN_ACTION_TITLE)
                    .to_owned(),
                section_title: localizer
                    .text(locale, MessageKey::SAFETY_ADMIN_ACTION_TITLE)
                    .to_owned(),
                rows: [
                    ("no_action", MessageKey::SAFETY_ADMIN_NO_ACTION),
                    ("warning", MessageKey::SAFETY_ADMIN_WARNING),
                    ("temporary_suspension", MessageKey::SAFETY_ADMIN_SUSPEND),
                    ("permanent_removal", MessageKey::SAFETY_ADMIN_REMOVE),
                ]
                .into_iter()
                .map(|(code, key)| ListRowSpec {
                    id: format!("safety.admin.action:{code}"),
                    title: localizer.text(locale, key).to_owned(),
                    description: None,
                })
                .collect(),
            },
        },
        SafetyAdminState::Confirm { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::SAFETY_ADMIN_CONFIRM_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![
                button(
                    "safety.admin.confirm",
                    localizer.text(locale, MessageKey::TRUST_CONFIRM_TITLE),
                ),
                button(
                    "safety.admin.cancel",
                    localizer.text(locale, MessageKey::NAV_BACK),
                ),
            ]),
        },
        SafetyAdminState::Done => ReplySpec {
            body: localizer
                .text(locale, MessageKey::SAFETY_ADMIN_RESOLVED_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![button(
                "safety.admin.queue",
                localizer.text(locale, MessageKey::SAFETY_ADMIN_QUEUE_TITLE),
            )]),
        },
    };
    if let Some(prefix) = prefix {
        reply.body = format!("{prefix}\n\n{}", reply.body);
    }
    reply
}

fn advance(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    next: SafetyAdminState,
    command: Option<BusinessCommand>,
) -> TurnPlan {
    let reply = reply(
        localizer,
        session.locale,
        &next,
        &context.safety_administrator,
        None,
    );
    TurnPlan {
        session_change: SessionChange::Advance {
            session_id: session.id,
            expected_version: session.version,
            next: ConversationState::SafetyAdministrator(next),
        },
        locale_change: None,
        business_command: command,
        reply,
        disposition: ConversationDisposition::Applied,
    }
}
fn invalid(
    localizer: &Localizer,
    context: &ConversationContext,
    state: &SafetyAdminState,
) -> TurnPlan {
    let locale = context
        .session
        .as_ref()
        .map_or(Locale::EnIn, |session| session.locale);
    match context.session.as_ref() {
        Some(session) => TurnPlan {
            session_change: SessionChange::Advance {
                session_id: session.id,
                expected_version: session.version,
                next: ConversationState::SafetyAdministrator(state.clone()),
            },
            locale_change: None,
            business_command: None,
            reply: reply(
                localizer,
                locale,
                state,
                &context.safety_administrator,
                Some(localizer.text(locale, MessageKey::INPUT_UNKNOWN_BODY)),
            ),
            disposition: ConversationDisposition::Unexpected,
        },
        None => TurnPlan {
            session_change: SessionChange::Create {
                next: ConversationState::SafetyAdministrator(state.clone()),
                locale,
            },
            locale_change: None,
            business_command: None,
            reply: reply(
                localizer,
                locale,
                state,
                &context.safety_administrator,
                None,
            ),
            disposition: ConversationDisposition::Recovered,
        },
    }
}
fn parse_action(value: &str) -> Option<SafetyAdminAction> {
    match value {
        "no_action" => Some(SafetyAdminAction::NoAction),
        "warning" => Some(SafetyAdminAction::Warning),
        "temporary_suspension" => Some(SafetyAdminAction::TemporarySuspension),
        "permanent_removal" => Some(SafetyAdminAction::PermanentRemoval),
        _ => None,
    }
}
fn action(input: &UserInput) -> Option<&str> {
    match input {
        UserInput::Action { id, .. } => Some(id.as_str()),
        _ => None,
    }
}
fn button(id: &str, title: &str) -> ButtonSpec {
    ButtonSpec {
        id: id.to_owned(),
        title: title.to_owned(),
    }
}
