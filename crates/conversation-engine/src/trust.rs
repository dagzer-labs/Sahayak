use crate::{
    BusinessCommand, ButtonSpec, ConversationContext, ConversationDisposition, ConversationState,
    ListRowSpec, ReplyControls, ReplySpec, SessionChange, SessionSnapshot, TrustCommand,
    TrustState, TrustView, TurnPlan, UserInput,
};
use sahayak_localization::{Locale, Localizer, MessageKey};

pub(crate) fn decide(
    localizer: &Localizer,
    context: &ConversationContext,
    state: &TrustState,
    input: &UserInput,
) -> TurnPlan {
    let Some(session) = context.session.as_ref() else {
        return invalid(localizer, context, state);
    };
    match state {
        TrustState::List => {
            if let Some(token) = action(input).and_then(|value| value.strip_prefix("trust.select:"))
                && context
                    .trust
                    .introductions
                    .iter()
                    .any(|item| item.reveal_token == token)
            {
                return advance(
                    localizer,
                    context,
                    session,
                    TrustState::Actions {
                        reveal_token: token.to_owned(),
                    },
                    None,
                );
            }
            invalid(localizer, context, state)
        }
        TrustState::Actions { reveal_token } => {
            let Some(introduction) = context
                .trust
                .introductions
                .iter()
                .find(|item| item.reveal_token == *reveal_token)
            else {
                return stale(localizer, context, state);
            };
            match action(input) {
                Some("trust.review") if !introduction.already_reviewed => advance(
                    localizer,
                    context,
                    session,
                    TrustState::ReviewConnection {
                        reveal_token: reveal_token.clone(),
                    },
                    None,
                ),
                Some("trust.report") if !introduction.already_reported => advance(
                    localizer,
                    context,
                    session,
                    TrustState::ReportCategory {
                        reveal_token: reveal_token.clone(),
                    },
                    None,
                ),
                Some("trust.block") if !introduction.already_blocked => advance(
                    localizer,
                    context,
                    session,
                    TrustState::ConfirmBlock {
                        reveal_token: reveal_token.clone(),
                    },
                    None,
                ),
                Some("nav.back") => advance(localizer, context, session, TrustState::List, None),
                _ => invalid(localizer, context, state),
            }
        }
        TrustState::ReviewConnection { reveal_token } => rating(input).map_or_else(
            || invalid(localizer, context, state),
            |connection| {
                advance(
                    localizer,
                    context,
                    session,
                    TrustState::ReviewResponsiveness {
                        reveal_token: reveal_token.clone(),
                        connection,
                    },
                    None,
                )
            },
        ),
        TrustState::ReviewResponsiveness {
            reveal_token,
            connection,
        } => rating(input).map_or_else(
            || invalid(localizer, context, state),
            |responsiveness| {
                advance(
                    localizer,
                    context,
                    session,
                    TrustState::ReviewCompletion {
                        reveal_token: reveal_token.clone(),
                        connection: *connection,
                        responsiveness,
                    },
                    None,
                )
            },
        ),
        TrustState::ReviewCompletion {
            reveal_token,
            connection,
            responsiveness,
        } => rating(input).map_or_else(
            || invalid(localizer, context, state),
            |completion| {
                advance(
                    localizer,
                    context,
                    session,
                    TrustState::ReviewFeedback {
                        reveal_token: reveal_token.clone(),
                        connection: *connection,
                        responsiveness: *responsiveness,
                        completion,
                    },
                    None,
                )
            },
        ),
        TrustState::ReviewFeedback {
            reveal_token,
            connection,
            responsiveness,
            completion,
        } => {
            let feedback = match input {
                UserInput::Action { id, .. } if id.as_str() == "trust.feedback.skip" => Some(None),
                UserInput::Text(text) if text.value().len() <= 1_000 => {
                    Some(Some(text.value().to_owned()))
                }
                _ => None,
            };
            feedback.map_or_else(
                || invalid(localizer, context, state),
                |written_feedback| {
                    advance(
                        localizer,
                        context,
                        session,
                        TrustState::Done {
                            outcome: "review_submitted".to_owned(),
                        },
                        Some(BusinessCommand::Trust(TrustCommand::SubmitReview {
                            reveal_token: reveal_token.clone(),
                            connection: *connection,
                            responsiveness: *responsiveness,
                            completion: *completion,
                            written_feedback,
                        })),
                    )
                },
            )
        }
        TrustState::ReportCategory { reveal_token } => {
            if let Some(category) =
                action(input).and_then(|value| value.strip_prefix("trust.category:"))
                && matches!(
                    category,
                    "spam"
                        | "harassment"
                        | "fraud"
                        | "unsafe_behavior"
                        | "identity_misrepresentation"
                        | "no_show"
                        | "other"
                )
            {
                return advance(
                    localizer,
                    context,
                    session,
                    TrustState::ReportBlock {
                        reveal_token: reveal_token.clone(),
                        category: category.to_owned(),
                    },
                    None,
                );
            }
            invalid(localizer, context, state)
        }
        TrustState::ReportBlock {
            reveal_token,
            category,
        } => match action(input) {
            Some("trust.report.block") | Some("trust.report.no_block") => advance(
                localizer,
                context,
                session,
                TrustState::ReportDescription {
                    reveal_token: reveal_token.clone(),
                    category: category.clone(),
                    block_subject: action(input) == Some("trust.report.block"),
                },
                None,
            ),
            _ => invalid(localizer, context, state),
        },
        TrustState::ReportDescription {
            reveal_token,
            category,
            block_subject,
        } => {
            let description = match input {
                UserInput::Action { id, .. } if id.as_str() == "trust.description.skip" => {
                    Some(None)
                }
                UserInput::Text(text) if text.value().len() <= 2_000 => {
                    Some(Some(text.value().to_owned()))
                }
                _ => None,
            };
            description.map_or_else(
                || invalid(localizer, context, state),
                |description| {
                    advance(
                        localizer,
                        context,
                        session,
                        TrustState::Done {
                            outcome: "report_submitted".to_owned(),
                        },
                        Some(BusinessCommand::Trust(TrustCommand::SubmitReport {
                            reveal_token: reveal_token.clone(),
                            category: category.clone(),
                            block_subject: *block_subject,
                            description,
                        })),
                    )
                },
            )
        }
        TrustState::ConfirmBlock { reveal_token } => match action(input) {
            Some("trust.block.confirm") => advance(
                localizer,
                context,
                session,
                TrustState::Done {
                    outcome: "blocked".to_owned(),
                },
                Some(BusinessCommand::Trust(TrustCommand::Block {
                    reveal_token: reveal_token.clone(),
                })),
            ),
            Some("trust.block.cancel") => advance(
                localizer,
                context,
                session,
                TrustState::Actions {
                    reveal_token: reveal_token.clone(),
                },
                None,
            ),
            _ => invalid(localizer, context, state),
        },
        TrustState::Done { .. } => match action(input) {
            Some("trust.list") => advance(localizer, context, session, TrustState::List, None),
            _ => invalid(localizer, context, state),
        },
    }
}

pub(crate) fn reply(
    localizer: &Localizer,
    locale: Locale,
    state: &TrustState,
    trust: &TrustView,
    prefix: Option<&str>,
) -> ReplySpec {
    let mut reply = match state {
        TrustState::List => list_reply(localizer, locale, trust),
        TrustState::Actions { reveal_token } => {
            actions_reply(localizer, locale, trust, reveal_token)
        }
        TrustState::ReviewConnection { .. } => {
            rating_reply(localizer, locale, MessageKey::TRUST_REVIEW_CONNECTION_BODY)
        }
        TrustState::ReviewResponsiveness { .. } => rating_reply(
            localizer,
            locale,
            MessageKey::TRUST_REVIEW_RESPONSIVENESS_BODY,
        ),
        TrustState::ReviewCompletion { .. } => {
            rating_reply(localizer, locale, MessageKey::TRUST_REVIEW_COMPLETION_BODY)
        }
        TrustState::ReviewFeedback { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::TRUST_REVIEW_FEEDBACK_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![button(
                "trust.feedback.skip",
                localizer.text(locale, MessageKey::TRUST_SKIP_TITLE),
            )]),
        },
        TrustState::ReportCategory { .. } => report_categories(localizer, locale),
        TrustState::ReportBlock { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::TRUST_REPORT_BLOCK_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![
                button(
                    "trust.report.block",
                    localizer.text(locale, MessageKey::TRUST_BLOCK_TITLE),
                ),
                button(
                    "trust.report.no_block",
                    localizer.text(locale, MessageKey::TRUST_NO_BLOCK_TITLE),
                ),
            ]),
        },
        TrustState::ReportDescription { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::TRUST_REPORT_DESCRIPTION_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![button(
                "trust.description.skip",
                localizer.text(locale, MessageKey::TRUST_SKIP_TITLE),
            )]),
        },
        TrustState::ConfirmBlock { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::TRUST_BLOCK_CONFIRM_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![
                button(
                    "trust.block.confirm",
                    localizer.text(locale, MessageKey::TRUST_CONFIRM_TITLE),
                ),
                button(
                    "trust.block.cancel",
                    localizer.text(locale, MessageKey::NAV_BACK),
                ),
            ]),
        },
        TrustState::Done { outcome } => ReplySpec {
            body: localizer
                .text(
                    locale,
                    if outcome == "review_submitted" {
                        MessageKey::TRUST_REVIEW_SUBMITTED_BODY
                    } else if outcome == "report_submitted" {
                        MessageKey::TRUST_REPORT_SUBMITTED_BODY
                    } else {
                        MessageKey::TRUST_BLOCKED_BODY
                    },
                )
                .to_owned(),
            controls: ReplyControls::Buttons(vec![button(
                "trust.list",
                localizer.text(locale, MessageKey::TRUST_LIST_TITLE),
            )]),
        },
    };
    if let Some(prefix) = prefix {
        reply.body = format!("{prefix}\n\n{}", reply.body);
    }
    reply
}

fn list_reply(localizer: &Localizer, locale: Locale, trust: &TrustView) -> ReplySpec {
    let rows: Vec<ListRowSpec> = trust
        .introductions
        .iter()
        .take(10)
        .map(|item| ListRowSpec {
            id: format!("trust.select:{}", item.reveal_token),
            title: item.counterpart_label.clone().unwrap_or_else(|| {
                localizer
                    .text(locale, MessageKey::TRUST_CUSTOMER_TITLE)
                    .to_owned()
            }),
            description: Some(item.category_code.clone()),
        })
        .collect();
    let controls = if rows.is_empty() {
        ReplyControls::None
    } else {
        ReplyControls::List {
            open_title: localizer
                .text(locale, MessageKey::TRUST_LIST_TITLE)
                .to_owned(),
            section_title: localizer
                .text(locale, MessageKey::TRUST_LIST_TITLE)
                .to_owned(),
            rows,
        }
    };
    ReplySpec {
        body: localizer
            .text(
                locale,
                if trust.introductions.is_empty() {
                    MessageKey::TRUST_EMPTY_BODY
                } else {
                    MessageKey::TRUST_LIST_BODY
                },
            )
            .to_owned(),
        controls,
    }
}

fn actions_reply(
    localizer: &Localizer,
    locale: Locale,
    trust: &TrustView,
    token: &str,
) -> ReplySpec {
    let introduction = trust
        .introductions
        .iter()
        .find(|item| item.reveal_token == token);
    let mut buttons = Vec::new();
    if introduction.is_some_and(|item| !item.already_reviewed) {
        buttons.push(button(
            "trust.review",
            localizer.text(locale, MessageKey::TRUST_REVIEW_TITLE),
        ));
    }
    if introduction.is_some_and(|item| !item.already_reported) {
        buttons.push(button(
            "trust.report",
            localizer.text(locale, MessageKey::TRUST_REPORT_TITLE),
        ));
    }
    if introduction.is_some_and(|item| !item.already_blocked) {
        buttons.push(button(
            "trust.block",
            localizer.text(locale, MessageKey::TRUST_BLOCK_TITLE),
        ));
    }
    ReplySpec {
        body: localizer
            .text(locale, MessageKey::TRUST_ACTIONS_BODY)
            .to_owned(),
        controls: ReplyControls::Buttons(buttons),
    }
}

fn rating_reply(localizer: &Localizer, locale: Locale, body: MessageKey) -> ReplySpec {
    ReplySpec {
        body: localizer.text(locale, body).to_owned(),
        controls: ReplyControls::List {
            open_title: localizer
                .text(locale, MessageKey::TRUST_RATING_TITLE)
                .to_owned(),
            section_title: localizer
                .text(locale, MessageKey::TRUST_RATING_TITLE)
                .to_owned(),
            rows: (1..=5)
                .map(|rating| ListRowSpec {
                    id: format!("trust.rating:{rating}"),
                    title: rating.to_string(),
                    description: None,
                })
                .collect(),
        },
    }
}

fn report_categories(localizer: &Localizer, locale: Locale) -> ReplySpec {
    let categories = [
        ("spam", MessageKey::TRUST_CATEGORY_SPAM),
        ("harassment", MessageKey::TRUST_CATEGORY_HARASSMENT),
        ("fraud", MessageKey::TRUST_CATEGORY_FRAUD),
        ("unsafe_behavior", MessageKey::TRUST_CATEGORY_UNSAFE),
        (
            "identity_misrepresentation",
            MessageKey::TRUST_CATEGORY_IDENTITY,
        ),
        ("no_show", MessageKey::TRUST_CATEGORY_NO_SHOW),
        ("other", MessageKey::TRUST_CATEGORY_OTHER),
    ];
    ReplySpec {
        body: localizer
            .text(locale, MessageKey::TRUST_REPORT_CATEGORY_BODY)
            .to_owned(),
        controls: ReplyControls::List {
            open_title: localizer
                .text(locale, MessageKey::TRUST_REPORT_TITLE)
                .to_owned(),
            section_title: localizer
                .text(locale, MessageKey::TRUST_REPORT_TITLE)
                .to_owned(),
            rows: categories
                .into_iter()
                .map(|(code, key)| ListRowSpec {
                    id: format!("trust.category:{code}"),
                    title: localizer.text(locale, key).to_owned(),
                    description: None,
                })
                .collect(),
        },
    }
}

fn advance(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    next: TrustState,
    command: Option<BusinessCommand>,
) -> TurnPlan {
    let reply = reply(localizer, session.locale, &next, &context.trust, None);
    TurnPlan {
        session_change: SessionChange::Advance {
            session_id: session.id,
            expected_version: session.version,
            next: ConversationState::Trust(next),
        },
        locale_change: None,
        business_command: command,
        reply,
        disposition: ConversationDisposition::Applied,
    }
}

fn invalid(localizer: &Localizer, context: &ConversationContext, state: &TrustState) -> TurnPlan {
    let locale = context
        .session
        .as_ref()
        .map_or(Locale::EnIn, |session| session.locale);
    match context.session.as_ref() {
        Some(session) => TurnPlan {
            session_change: SessionChange::Advance {
                session_id: session.id,
                expected_version: session.version,
                next: ConversationState::Trust(state.clone()),
            },
            locale_change: None,
            business_command: None,
            reply: reply(
                localizer,
                locale,
                state,
                &context.trust,
                Some(localizer.text(locale, MessageKey::INPUT_UNKNOWN_BODY)),
            ),
            disposition: ConversationDisposition::Unexpected,
        },
        None => TurnPlan {
            session_change: SessionChange::Create {
                next: ConversationState::Trust(state.clone()),
                locale,
            },
            locale_change: None,
            business_command: None,
            reply: reply(localizer, locale, state, &context.trust, None),
            disposition: ConversationDisposition::Recovered,
        },
    }
}

fn stale(localizer: &Localizer, context: &ConversationContext, state: &TrustState) -> TurnPlan {
    let mut plan = invalid(localizer, context, state);
    plan.reply.body = localizer
        .text(
            context
                .session
                .as_ref()
                .map_or(Locale::EnIn, |session| session.locale),
            MessageKey::TRUST_STALE_BODY,
        )
        .to_owned();
    plan
}

fn action(input: &UserInput) -> Option<&str> {
    match input {
        UserInput::Action { id, .. } => Some(id.as_str()),
        _ => None,
    }
}
fn rating(input: &UserInput) -> Option<u8> {
    action(input)?
        .strip_prefix("trust.rating:")?
        .parse()
        .ok()
        .filter(|value| (1..=5).contains(value))
}
fn button(id: &str, title: &str) -> ButtonSpec {
    ButtonSpec {
        id: id.to_owned(),
        title: title.to_owned(),
    }
}
