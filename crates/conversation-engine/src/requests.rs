use crate::{
    BusinessCommand, ButtonSpec, ConnectionCommand, ConnectionsView, ConversationContext,
    ConversationDisposition, ConversationState, ListRowSpec, ProfessionalRequestsState,
    ReplyControls, ReplySpec, ServiceCategory, SessionChange, SessionSnapshot, TurnPlan, UserInput,
};
use sahayak_localization::{Locale, Localizer, MessageKey};

pub(crate) fn decide(
    localizer: &Localizer,
    context: &ConversationContext,
    state: &ProfessionalRequestsState,
    input: &UserInput,
) -> TurnPlan {
    let Some(session) = context.session.as_ref() else {
        return invalid(localizer, context, state);
    };
    match state {
        ProfessionalRequestsState::List => {
            if let Some(token) =
                action(input).and_then(|value| value.strip_prefix("request.select:"))
                && let Some(request) = context
                    .connections
                    .pending
                    .iter()
                    .find(|item| item.request_token == token)
            {
                return advance(
                    localizer,
                    context,
                    session,
                    ProfessionalRequestsState::Inspect {
                        request_token: token.to_owned(),
                        version: request.version,
                    },
                    None,
                    MessageKey::REQUESTS_INSPECT_BODY,
                );
            }
            invalid(localizer, context, state)
        }
        ProfessionalRequestsState::Inspect {
            request_token,
            version,
        } => match action(input) {
            Some("request.accept") => advance(
                localizer,
                context,
                session,
                ProfessionalRequestsState::Confirm {
                    request_token: request_token.clone(),
                    version: *version,
                    accept: true,
                },
                None,
                MessageKey::REQUESTS_ACCEPT_CONFIRM_BODY,
            ),
            Some("request.decline") => advance(
                localizer,
                context,
                session,
                ProfessionalRequestsState::Confirm {
                    request_token: request_token.clone(),
                    version: *version,
                    accept: false,
                },
                None,
                MessageKey::REQUESTS_DECLINE_CONFIRM_BODY,
            ),
            Some("nav.back") => advance(
                localizer,
                context,
                session,
                ProfessionalRequestsState::List,
                None,
                MessageKey::REQUESTS_LIST_BODY,
            ),
            _ => invalid(localizer, context, state),
        },
        ProfessionalRequestsState::Confirm {
            request_token,
            version,
            accept,
        } => match action(input) {
            Some("request.confirm") => advance(
                localizer,
                context,
                session,
                ProfessionalRequestsState::List,
                Some(BusinessCommand::Connection(ConnectionCommand::Respond {
                    request_token: request_token.clone(),
                    expected_version: *version,
                    accept: *accept,
                })),
                if *accept {
                    MessageKey::REQUESTS_ACCEPTED_BODY
                } else {
                    MessageKey::REQUESTS_DECLINED_BODY
                },
            ),
            Some("request.cancel") => advance(
                localizer,
                context,
                session,
                ProfessionalRequestsState::Inspect {
                    request_token: request_token.clone(),
                    version: *version,
                },
                None,
                MessageKey::REQUESTS_INSPECT_BODY,
            ),
            _ => invalid(localizer, context, state),
        },
    }
}

pub(crate) fn reply(
    localizer: &Localizer,
    locale: Locale,
    state: &ProfessionalRequestsState,
    connections: &ConnectionsView,
    prefix: Option<&str>,
) -> ReplySpec {
    let mut reply = match state {
        ProfessionalRequestsState::List => list_reply(localizer, locale, connections),
        ProfessionalRequestsState::Inspect { request_token, .. } => {
            inspect_reply(localizer, locale, connections, request_token)
        }
        ProfessionalRequestsState::Confirm { accept, .. } => ReplySpec {
            body: localizer
                .text(
                    locale,
                    if *accept {
                        MessageKey::REQUESTS_ACCEPT_CONFIRM_BODY
                    } else {
                        MessageKey::REQUESTS_DECLINE_CONFIRM_BODY
                    },
                )
                .to_owned(),
            controls: ReplyControls::Buttons(vec![
                button(
                    "request.confirm",
                    localizer.text(locale, MessageKey::REQUESTS_CONFIRM_TITLE),
                ),
                button(
                    "request.cancel",
                    localizer.text(locale, MessageKey::REQUESTS_CANCEL_TITLE),
                ),
            ]),
        },
    };
    if let Some(prefix) = prefix {
        reply.body = format!("{prefix}\n\n{}", reply.body);
    }
    reply
}

fn list_reply(localizer: &Localizer, locale: Locale, connections: &ConnectionsView) -> ReplySpec {
    let rows = connections
        .pending
        .iter()
        .take(10)
        .map(|request| ListRowSpec {
            id: format!("request.select:{}", request.request_token),
            title: match request.category {
                ServiceCategory::Plumber => {
                    localizer.text(locale, MessageKey::DISCOVERY_CATEGORY_PLUMBER)
                }
                ServiceCategory::Electrician => {
                    localizer.text(locale, MessageKey::DISCOVERY_CATEGORY_ELECTRICIAN)
                }
            }
            .to_owned(),
            description: Some(format!(
                "{} · {}",
                request.distance_label, request.requested_time
            )),
        })
        .collect();
    ReplySpec {
        body: localizer
            .text(
                locale,
                if connections.pending.is_empty() {
                    MessageKey::REQUESTS_EMPTY_BODY
                } else {
                    MessageKey::REQUESTS_LIST_BODY
                },
            )
            .to_owned(),
        controls: ReplyControls::List {
            open_title: localizer
                .text(locale, MessageKey::REQUESTS_OPEN_TITLE)
                .to_owned(),
            section_title: localizer
                .text(locale, MessageKey::REQUESTS_OPEN_TITLE)
                .to_owned(),
            rows,
        },
    }
}

fn inspect_reply(
    localizer: &Localizer,
    locale: Locale,
    connections: &ConnectionsView,
    token: &str,
) -> ReplySpec {
    let body = connections
        .pending
        .iter()
        .find(|item| item.request_token == token)
        .map(|item| {
            format!(
                "{}\n\n{} · {} · {}",
                localizer.text(locale, MessageKey::REQUESTS_INSPECT_BODY),
                item.issue_code,
                item.requested_time,
                item.distance_label,
            )
        })
        .unwrap_or_else(|| {
            localizer
                .text(locale, MessageKey::REQUESTS_STALE_BODY)
                .to_owned()
        });
    ReplySpec {
        body,
        controls: ReplyControls::Buttons(vec![
            button(
                "request.accept",
                localizer.text(locale, MessageKey::REQUESTS_ACCEPT_TITLE),
            ),
            button(
                "request.decline",
                localizer.text(locale, MessageKey::REQUESTS_DECLINE_TITLE),
            ),
            button("nav.back", localizer.text(locale, MessageKey::NAV_BACK)),
        ]),
    }
}

fn advance(
    localizer: &Localizer,
    _context: &ConversationContext,
    session: &SessionSnapshot,
    next: ProfessionalRequestsState,
    command: Option<BusinessCommand>,
    body: MessageKey,
) -> TurnPlan {
    TurnPlan {
        session_change: SessionChange::Advance {
            session_id: session.id,
            expected_version: session.version,
            next: ConversationState::ProfessionalRequests(next),
        },
        locale_change: None,
        business_command: command,
        reply: ReplySpec {
            body: localizer.text(session.locale, body).to_owned(),
            controls: ReplyControls::None,
        },
        disposition: ConversationDisposition::Applied,
    }
}

fn invalid(
    localizer: &Localizer,
    context: &ConversationContext,
    state: &ProfessionalRequestsState,
) -> TurnPlan {
    let locale = context
        .session
        .as_ref()
        .map_or(Locale::EnIn, |session| session.locale);
    if let Some(session) = context.session.as_ref() {
        TurnPlan {
            session_change: SessionChange::Advance {
                session_id: session.id,
                expected_version: session.version,
                next: ConversationState::ProfessionalRequests(state.clone()),
            },
            locale_change: None,
            business_command: None,
            reply: reply(
                localizer,
                locale,
                state,
                &context.connections,
                Some(localizer.text(locale, MessageKey::INPUT_UNKNOWN_BODY)),
            ),
            disposition: ConversationDisposition::Unexpected,
        }
    } else {
        TurnPlan {
            session_change: SessionChange::Create {
                next: ConversationState::ProfessionalRequests(state.clone()),
                locale,
            },
            locale_change: None,
            business_command: None,
            reply: reply(localizer, locale, state, &context.connections, None),
            disposition: ConversationDisposition::Recovered,
        }
    }
}

fn button(id: &str, title: &str) -> ButtonSpec {
    ButtonSpec {
        id: id.to_owned(),
        title: title.to_owned(),
    }
}

fn action(input: &UserInput) -> Option<&str> {
    match input {
        UserInput::Action { id, .. } => Some(id.as_str()),
        _ => None,
    }
}
