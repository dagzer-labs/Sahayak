use crate::{
    BusinessCommand, ButtonSpec, ConnectionCommand, ContactMode, ConversationContext,
    ConversationDisposition, ConversationState, DiscoveryCommand, DiscoveryState, DiscoveryStatus,
    DiscoveryView, ListRowSpec, ReplyControls, ReplySpec, RequestedTimeChoice, ServiceCategory,
    SessionChange, SessionSnapshot, TurnPlan, UserInput,
};
use sahayak_localization::{Locale, Localizer, MessageKey};

pub(crate) fn entry_state(
    view: &DiscoveryView,
    connections: &crate::ConnectionsView,
) -> DiscoveryState {
    match view.status {
        DiscoveryStatus::None => DiscoveryState::Category,
        DiscoveryStatus::Collecting if view.cards.is_empty() => DiscoveryState::Location {
            category: view.category.unwrap_or(ServiceCategory::Plumber),
        },
        DiscoveryStatus::Results | DiscoveryStatus::NoResults => DiscoveryState::Results {
            request_token: view
                .request_token
                .clone()
                .unwrap_or_else(|| "missing".to_owned()),
        },
        DiscoveryStatus::Waiting => DiscoveryState::Waiting {
            connection_token: connections
                .customer_pending
                .as_ref()
                .map(|pending| pending.request_token.clone())
                .or_else(|| view.request_token.clone())
                .unwrap_or_else(|| "missing".to_owned()),
            connection_version: connections
                .customer_pending
                .as_ref()
                .map(|pending| pending.version)
                .or(view.version)
                .unwrap_or(1),
        },
        DiscoveryStatus::Connected => DiscoveryState::Recent,
        DiscoveryStatus::Collecting => DiscoveryState::Category,
    }
}

pub(crate) fn decide(
    localizer: &Localizer,
    context: &ConversationContext,
    state: &DiscoveryState,
    input: &UserInput,
) -> TurnPlan {
    let Some(session) = context.session.as_ref() else {
        return invalid(localizer, context, state);
    };
    match state {
        DiscoveryState::Category => match action(input) {
            Some("discovery.category.plumber") => {
                begin(localizer, context, session, ServiceCategory::Plumber)
            }
            Some("discovery.category.electrician") => {
                begin(localizer, context, session, ServiceCategory::Electrician)
            }
            _ => invalid(localizer, context, state),
        },
        DiscoveryState::Location { category } => {
            if matches!(input, UserInput::Location) {
                let Some((token, version)) = current_request(&context.discovery) else {
                    return invalid(localizer, context, state);
                };
                advance(
                    localizer,
                    context,
                    session,
                    DiscoveryState::Time {
                        category: *category,
                    },
                    Some(BusinessCommand::Discovery(
                        DiscoveryCommand::CurrentInboundLocation {
                            request_token: token,
                            expected_version: version,
                        },
                    )),
                    MessageKey::DISCOVERY_TIME_BODY,
                    ConversationDisposition::Applied,
                )
            } else {
                invalid(localizer, context, state)
            }
        }
        DiscoveryState::Time { category } => {
            let requested_time = match action(input) {
                Some("discovery.time.now") => Some(RequestedTimeChoice::Now),
                Some("discovery.time.today") => Some(RequestedTimeChoice::Today),
                Some("discovery.time.flexible") => Some(RequestedTimeChoice::Flexible),
                _ => None,
            };
            requested_time.map_or_else(
                || invalid(localizer, context, state),
                |requested_time| {
                    advance(
                        localizer,
                        context,
                        session,
                        DiscoveryState::Issue {
                            category: *category,
                            requested_time,
                        },
                        None,
                        issue_body(*category),
                        ConversationDisposition::Applied,
                    )
                },
            )
        }
        DiscoveryState::Issue {
            category,
            requested_time,
        } => {
            let issue = issue_code(*category, action(input));
            let Some(issue) = issue else {
                return invalid(localizer, context, state);
            };
            let Some((token, version)) = current_request(&context.discovery) else {
                return invalid(localizer, context, state);
            };
            advance(
                localizer,
                context,
                session,
                DiscoveryState::SearchComplete {
                    request_token: token.clone(),
                },
                Some(BusinessCommand::Discovery(DiscoveryCommand::Search {
                    request_token: token,
                    expected_version: version,
                    requested_time: *requested_time,
                    issue_code: issue.to_owned(),
                })),
                MessageKey::DISCOVERY_SEARCH_COMPLETE_BODY,
                ConversationDisposition::Applied,
            )
        }
        DiscoveryState::SearchComplete { request_token } => {
            if action(input) == Some("discovery.view_results") {
                advance(
                    localizer,
                    context,
                    session,
                    DiscoveryState::Results {
                        request_token: request_token.clone(),
                    },
                    None,
                    MessageKey::DISCOVERY_RESULTS_BODY,
                    ConversationDisposition::Applied,
                )
            } else {
                invalid(localizer, context, state)
            }
        }
        DiscoveryState::Results { request_token } => {
            results(localizer, context, session, state, request_token, input)
        }
        DiscoveryState::ConfirmSelection {
            request_token,
            request_version,
            candidate_token,
            contact_mode,
        } => match action(input) {
            Some("discovery.confirm.yes") => advance(
                localizer,
                context,
                session,
                DiscoveryState::Waiting {
                    connection_token: request_token.clone(),
                    connection_version: 1,
                },
                Some(BusinessCommand::Connection(ConnectionCommand::Select {
                    request_token: request_token.clone(),
                    request_version: *request_version,
                    candidate_token: candidate_token.clone(),
                })),
                if *contact_mode == ContactMode::Direct {
                    MessageKey::DISCOVERY_DIRECT_PROCESSING_BODY
                } else {
                    MessageKey::DISCOVERY_REQUEST_SENT_BODY
                },
                ConversationDisposition::Applied,
            ),
            Some("discovery.confirm.cancel") => advance(
                localizer,
                context,
                session,
                DiscoveryState::Results {
                    request_token: request_token.clone(),
                },
                None,
                MessageKey::DISCOVERY_RESULTS_BODY,
                ConversationDisposition::Applied,
            ),
            _ => invalid(localizer, context, state),
        },
        DiscoveryState::Waiting { .. } => {
            if action(input) == Some("discovery.request.cancel")
                && let Some(pending) = context.connections.customer_pending.as_ref()
            {
                return advance(
                    localizer,
                    context,
                    session,
                    DiscoveryState::Results {
                        request_token: context
                            .discovery
                            .request_token
                            .clone()
                            .unwrap_or_else(|| "missing".to_owned()),
                    },
                    Some(BusinessCommand::Connection(ConnectionCommand::Cancel {
                        request_token: pending.request_token.clone(),
                        expected_version: pending.version,
                    })),
                    MessageKey::DISCOVERY_REQUEST_CANCELLED_BODY,
                    ConversationDisposition::Applied,
                );
            }
            invalid(localizer, context, state)
        }
        DiscoveryState::Recent => {
            if let Some(token) =
                action(input).and_then(|value| value.strip_prefix("recent.select:"))
                && context
                    .connections
                    .recent
                    .iter()
                    .any(|item| item.reveal_token == token)
            {
                return advance(
                    localizer,
                    context,
                    session,
                    DiscoveryState::Recent,
                    Some(BusinessCommand::Connection(
                        ConnectionCommand::RepeatReveal {
                            reveal_token: token.to_owned(),
                        },
                    )),
                    MessageKey::RECENT_CONTACT_PROCESSING_BODY,
                    ConversationDisposition::Applied,
                );
            }
            invalid(localizer, context, state)
        }
    }
}

pub(crate) fn reply(
    localizer: &Localizer,
    locale: Locale,
    state: &DiscoveryState,
    view: &DiscoveryView,
    connections: &crate::ConnectionsView,
    prefix: Option<&str>,
) -> ReplySpec {
    let mut reply = match state {
        DiscoveryState::Category => ReplySpec {
            body: localizer
                .text(locale, MessageKey::DISCOVERY_CATEGORY_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![
                button(
                    "discovery.category.plumber",
                    localizer.text(locale, MessageKey::DISCOVERY_CATEGORY_PLUMBER),
                ),
                button(
                    "discovery.category.electrician",
                    localizer.text(locale, MessageKey::DISCOVERY_CATEGORY_ELECTRICIAN),
                ),
            ]),
        },
        DiscoveryState::Location { .. } => {
            text(localizer, locale, MessageKey::DISCOVERY_LOCATION_BODY)
        }
        DiscoveryState::Time { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::DISCOVERY_TIME_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![
                button(
                    "discovery.time.now",
                    localizer.text(locale, MessageKey::DISCOVERY_TIME_NOW),
                ),
                button(
                    "discovery.time.today",
                    localizer.text(locale, MessageKey::DISCOVERY_TIME_TODAY),
                ),
                button(
                    "discovery.time.flexible",
                    localizer.text(locale, MessageKey::DISCOVERY_TIME_FLEXIBLE),
                ),
            ]),
        },
        DiscoveryState::Issue { category, .. } => issue_reply(localizer, locale, *category),
        DiscoveryState::SearchComplete { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::DISCOVERY_SEARCH_COMPLETE_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![button(
                "discovery.view_results",
                localizer.text(locale, MessageKey::DISCOVERY_VIEW_RESULTS),
            )]),
        },
        DiscoveryState::Results { .. } => result_reply(localizer, locale, view),
        DiscoveryState::ConfirmSelection { contact_mode, .. } => ReplySpec {
            body: localizer
                .text(
                    locale,
                    if *contact_mode == ContactMode::Direct {
                        MessageKey::DISCOVERY_CONFIRM_DIRECT_BODY
                    } else {
                        MessageKey::DISCOVERY_CONFIRM_APPROVAL_BODY
                    },
                )
                .to_owned(),
            controls: ReplyControls::Buttons(vec![
                button(
                    "discovery.confirm.yes",
                    localizer.text(locale, MessageKey::DISCOVERY_CONFIRM_YES),
                ),
                button(
                    "discovery.confirm.cancel",
                    localizer.text(locale, MessageKey::DISCOVERY_CONFIRM_CANCEL),
                ),
            ]),
        },
        DiscoveryState::Waiting { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::DISCOVERY_WAITING_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![button(
                "discovery.request.cancel",
                localizer.text(locale, MessageKey::DISCOVERY_REQUEST_CANCEL_TITLE),
            )]),
        },
        DiscoveryState::Recent => recent_reply(localizer, locale, connections),
    };
    if let Some(prefix) = prefix {
        reply.body = format!("{prefix}\n\n{}", reply.body);
    }
    reply
}

fn begin(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    category: ServiceCategory,
) -> TurnPlan {
    advance(
        localizer,
        context,
        session,
        DiscoveryState::Location { category },
        Some(BusinessCommand::Discovery(DiscoveryCommand::Begin {
            category,
        })),
        MessageKey::DISCOVERY_LOCATION_BODY,
        ConversationDisposition::Applied,
    )
}

fn results(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    state: &DiscoveryState,
    request_token: &str,
    input: &UserInput,
) -> TurnPlan {
    let Some(request) = current_request(&context.discovery) else {
        return invalid(localizer, context, state);
    };
    if request.0 != request_token {
        return invalid(localizer, context, state);
    }
    match action(input) {
        Some("discovery.show_more") => advance(
            localizer,
            context,
            session,
            DiscoveryState::SearchComplete {
                request_token: request_token.to_owned(),
            },
            Some(BusinessCommand::Discovery(DiscoveryCommand::ShowMore {
                request_token: request_token.to_owned(),
                expected_version: request.1,
            })),
            MessageKey::DISCOVERY_SEARCH_COMPLETE_BODY,
            ConversationDisposition::Applied,
        ),
        Some("discovery.expand") => advance(
            localizer,
            context,
            session,
            DiscoveryState::SearchComplete {
                request_token: request_token.to_owned(),
            },
            Some(BusinessCommand::Discovery(DiscoveryCommand::ExpandRadius {
                request_token: request_token.to_owned(),
                expected_version: request.1,
            })),
            MessageKey::DISCOVERY_SEARCH_COMPLETE_BODY,
            ConversationDisposition::Applied,
        ),
        Some(value) if value.starts_with("discovery.select:") => {
            let token = value.trim_start_matches("discovery.select:");
            let Some(card) = context
                .discovery
                .cards
                .iter()
                .find(|card| card.candidate_token == token)
            else {
                return invalid(localizer, context, state);
            };
            advance(
                localizer,
                context,
                session,
                DiscoveryState::ConfirmSelection {
                    request_token: request_token.to_owned(),
                    request_version: request.1,
                    candidate_token: token.to_owned(),
                    contact_mode: card.contact_mode,
                },
                None,
                if card.contact_mode == ContactMode::Direct {
                    MessageKey::DISCOVERY_CONFIRM_DIRECT_BODY
                } else {
                    MessageKey::DISCOVERY_CONFIRM_APPROVAL_BODY
                },
                ConversationDisposition::Applied,
            )
        }
        _ => invalid(localizer, context, state),
    }
}

fn result_reply(localizer: &Localizer, locale: Locale, view: &DiscoveryView) -> ReplySpec {
    if view.cards.is_empty() {
        let mut rows = Vec::new();
        if view.radius_km.is_some_and(|radius| radius < 25) {
            rows.push(ListRowSpec {
                id: "discovery.expand".to_owned(),
                title: localizer
                    .text(locale, MessageKey::DISCOVERY_EXPAND_TITLE)
                    .to_owned(),
                description: Some(
                    localizer
                        .text(locale, MessageKey::DISCOVERY_EXPAND_DESC)
                        .to_owned(),
                ),
            });
        }
        return ReplySpec {
            body: localizer
                .text(locale, MessageKey::DISCOVERY_NO_RESULTS_BODY)
                .to_owned(),
            controls: ReplyControls::List {
                open_title: localizer
                    .text(locale, MessageKey::DISCOVERY_RESULTS_OPEN)
                    .to_owned(),
                section_title: localizer
                    .text(locale, MessageKey::DISCOVERY_RESULTS_SECTION)
                    .to_owned(),
                rows,
            },
        };
    }
    let mut body = localizer
        .text(locale, MessageKey::DISCOVERY_RESULTS_BODY)
        .to_owned();
    let mut rows = Vec::new();
    for (index, card) in view.cards.iter().take(3).enumerate() {
        body.push_str(&format!(
            "\n\n{}. {} ({})\n{} · {}{}",
            index + 1,
            card.display_name,
            card.public_reference,
            localized_distance(localizer, locale, &card.distance_label),
            localized_availability(localizer, locale, &card.availability_label),
            if card.identity_checked {
                format!(
                    " · {}",
                    localizer.text(locale, MessageKey::DISCOVERY_IDENTITY_CHECKED)
                )
            } else {
                String::new()
            }
        ));
        rows.push(ListRowSpec {
            id: format!("discovery.select:{}", card.candidate_token),
            title: truncate(&card.display_name, 24),
            description: Some(format!(
                "{} · {}",
                localized_distance(localizer, locale, &card.distance_label),
                if card.contact_mode == ContactMode::Direct {
                    localizer.text(locale, MessageKey::DISCOVERY_DIRECT_LABEL)
                } else {
                    localizer.text(locale, MessageKey::DISCOVERY_APPROVAL_LABEL)
                }
            )),
        });
    }
    if view.has_more {
        rows.push(ListRowSpec {
            id: "discovery.show_more".to_owned(),
            title: localizer
                .text(locale, MessageKey::DISCOVERY_SHOW_MORE_TITLE)
                .to_owned(),
            description: Some(
                localizer
                    .text(locale, MessageKey::DISCOVERY_SHOW_MORE_DESC)
                    .to_owned(),
            ),
        });
    }
    ReplySpec {
        body,
        controls: ReplyControls::List {
            open_title: localizer
                .text(locale, MessageKey::DISCOVERY_RESULTS_OPEN)
                .to_owned(),
            section_title: localizer
                .text(locale, MessageKey::DISCOVERY_RESULTS_SECTION)
                .to_owned(),
            rows,
        },
    }
}

fn issue_reply(localizer: &Localizer, locale: Locale, category: ServiceCategory) -> ReplySpec {
    let body = issue_body(category);
    let rows = match category {
        ServiceCategory::Plumber => vec![
            issue_row(
                localizer,
                locale,
                "leak_repair",
                MessageKey::DISCOVERY_ISSUE_LEAK,
            ),
            issue_row(
                localizer,
                locale,
                "drain_blockage",
                MessageKey::DISCOVERY_ISSUE_BLOCKAGE,
            ),
            issue_row(
                localizer,
                locale,
                "installation",
                MessageKey::DISCOVERY_ISSUE_INSTALLATION,
            ),
            issue_row(
                localizer,
                locale,
                "other",
                MessageKey::DISCOVERY_ISSUE_OTHER,
            ),
        ],
        ServiceCategory::Electrician => vec![
            issue_row(
                localizer,
                locale,
                "power_outage",
                MessageKey::DISCOVERY_ISSUE_OUTAGE,
            ),
            issue_row(
                localizer,
                locale,
                "wiring",
                MessageKey::DISCOVERY_ISSUE_WIRING,
            ),
            issue_row(
                localizer,
                locale,
                "installation",
                MessageKey::DISCOVERY_ISSUE_INSTALLATION,
            ),
            issue_row(
                localizer,
                locale,
                "other",
                MessageKey::DISCOVERY_ISSUE_OTHER,
            ),
        ],
    };
    ReplySpec {
        body: localizer.text(locale, body).to_owned(),
        controls: ReplyControls::List {
            open_title: localizer
                .text(locale, MessageKey::DISCOVERY_ISSUE_OPEN)
                .to_owned(),
            section_title: localizer.text(locale, body).to_owned(),
            rows,
        },
    }
}

fn issue_row(localizer: &Localizer, locale: Locale, code: &str, key: MessageKey) -> ListRowSpec {
    ListRowSpec {
        id: format!("discovery.issue.{code}"),
        title: localizer.text(locale, key).to_owned(),
        description: None,
    }
}

fn recent_reply(
    localizer: &Localizer,
    locale: Locale,
    connections: &crate::ConnectionsView,
) -> ReplySpec {
    let rows = connections
        .recent
        .iter()
        .take(10)
        .map(|contact| ListRowSpec {
            id: format!("recent.select:{}", contact.reveal_token),
            title: truncate(&contact.display_name, 24),
            description: Some(contact.public_reference.clone()),
        })
        .collect();
    ReplySpec {
        body: localizer
            .text(
                locale,
                if connections.recent.is_empty() {
                    MessageKey::RECENT_CONTACTS_EMPTY_BODY
                } else {
                    MessageKey::RECENT_CONTACTS_BODY
                },
            )
            .to_owned(),
        controls: ReplyControls::List {
            open_title: localizer
                .text(locale, MessageKey::RECENT_CONTACTS_OPEN)
                .to_owned(),
            section_title: localizer
                .text(locale, MessageKey::RECENT_CONTACTS_OPEN)
                .to_owned(),
            rows,
        },
    }
}

fn issue_body(category: ServiceCategory) -> MessageKey {
    match category {
        ServiceCategory::Plumber => MessageKey::DISCOVERY_ISSUE_PLUMBER_BODY,
        ServiceCategory::Electrician => MessageKey::DISCOVERY_ISSUE_ELECTRICIAN_BODY,
    }
}

fn issue_code(category: ServiceCategory, action: Option<&str>) -> Option<&'static str> {
    match (category, action) {
        (ServiceCategory::Plumber, Some("discovery.issue.leak_repair")) => Some("leak_repair"),
        (ServiceCategory::Plumber, Some("discovery.issue.drain_blockage")) => {
            Some("drain_blockage")
        }
        (ServiceCategory::Electrician, Some("discovery.issue.power_outage")) => {
            Some("power_outage")
        }
        (ServiceCategory::Electrician, Some("discovery.issue.wiring")) => Some("wiring"),
        (_, Some("discovery.issue.installation")) => Some("installation"),
        (_, Some("discovery.issue.other")) => Some("other"),
        _ => None,
    }
}

fn current_request(view: &DiscoveryView) -> Option<(String, i64)> {
    Some((view.request_token.clone()?, view.version?))
}

fn advance(
    localizer: &Localizer,
    _context: &ConversationContext,
    session: &SessionSnapshot,
    next: DiscoveryState,
    command: Option<BusinessCommand>,
    body: MessageKey,
    disposition: ConversationDisposition,
) -> TurnPlan {
    TurnPlan {
        session_change: SessionChange::Advance {
            session_id: session.id,
            expected_version: session.version,
            next: ConversationState::Discovery(next),
        },
        locale_change: None,
        business_command: command,
        reply: ReplySpec {
            body: localizer.text(session.locale, body).to_owned(),
            controls: ReplyControls::None,
        },
        disposition,
    }
}

fn invalid(
    localizer: &Localizer,
    context: &ConversationContext,
    state: &DiscoveryState,
) -> TurnPlan {
    let Some(session) = context.session.as_ref() else {
        let locale = context.confirmed_locale.unwrap_or(Locale::EnIn);
        return TurnPlan {
            session_change: SessionChange::Create {
                next: ConversationState::Discovery(state.clone()),
                locale,
            },
            locale_change: None,
            business_command: None,
            reply: reply(
                localizer,
                locale,
                state,
                &context.discovery,
                &context.connections,
                Some(localizer.text(locale, MessageKey::INPUT_UNKNOWN_BODY)),
            ),
            disposition: ConversationDisposition::Unexpected,
        };
    };
    TurnPlan {
        session_change: SessionChange::Advance {
            session_id: session.id,
            expected_version: session.version,
            next: ConversationState::Discovery(state.clone()),
        },
        locale_change: None,
        business_command: None,
        reply: reply(
            localizer,
            session.locale,
            state,
            &context.discovery,
            &context.connections,
            Some(localizer.text(session.locale, MessageKey::INPUT_UNKNOWN_BODY)),
        ),
        disposition: ConversationDisposition::Unexpected,
    }
}

fn text(localizer: &Localizer, locale: Locale, key: MessageKey) -> ReplySpec {
    ReplySpec {
        body: localizer.text(locale, key).to_owned(),
        controls: ReplyControls::None,
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

fn truncate(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

fn localized_distance<'a>(localizer: &'a Localizer, locale: Locale, code: &str) -> &'a str {
    match code {
        "under_1_km" => localizer.text(locale, MessageKey::DISCOVERY_DISTANCE_UNDER_ONE),
        "under_5_km" => localizer.text(locale, MessageKey::DISCOVERY_DISTANCE_UNDER_FIVE),
        "under_10_km" => localizer.text(locale, MessageKey::DISCOVERY_DISTANCE_UNDER_TEN),
        _ => localizer.text(locale, MessageKey::DISCOVERY_DISTANCE_FARTHER),
    }
}

fn localized_availability<'a>(localizer: &'a Localizer, locale: Locale, code: &str) -> &'a str {
    if code == "recently_confirmed" {
        localizer.text(locale, MessageKey::DISCOVERY_AVAILABLE_RECENT)
    } else {
        localizer.text(locale, MessageKey::DISCOVERY_AVAILABLE_NOW)
    }
}
