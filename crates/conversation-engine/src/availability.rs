use crate::{
    AvailabilityCommand, AvailabilityDuration, AvailabilityIneligibility, AvailabilityIntent,
    AvailabilityObservation, AvailabilityOutcome, AvailabilityState, AvailabilityView,
    BusinessCommand, ButtonSpec, ConversationContext, ConversationDisposition, ConversationState,
    ListRowSpec, ReplyControls, ReplySpec, SessionChange, SessionSnapshot, TurnPlan, UserInput,
};
use sahayak_localization::{Locale, Localizer, MessageKey};

pub(crate) fn entry_state(view: AvailabilityView) -> AvailabilityState {
    AvailabilityState::Status {
        observation: view.observation(),
    }
}

pub(crate) fn decide(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    state: &AvailabilityState,
    input: &UserInput,
) -> TurnPlan {
    match state {
        AvailabilityState::Status { observation } => {
            status(localizer, context, session, *observation, input)
        }
        AvailabilityState::ChooseDuration {
            observation,
            intent,
        } => choose_duration(localizer, context, session, *observation, *intent, input),
        AvailabilityState::ConfirmStop { observation } => {
            confirm_stop(localizer, context, session, *observation, input)
        }
        AvailabilityState::Changed { .. } => changed(localizer, context, session, input),
    }
}

pub(crate) fn stale(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
) -> TurnPlan {
    to_status(
        localizer,
        context,
        session,
        Some(localizer.text(session.locale, MessageKey::SELECTION_STALE_BODY)),
        ConversationDisposition::Stale,
    )
}

pub(crate) fn back_to_status(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
) -> TurnPlan {
    to_status(
        localizer,
        context,
        session,
        None,
        ConversationDisposition::Applied,
    )
}

fn status(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    expected: AvailabilityObservation,
    input: &UserInput,
) -> TurnPlan {
    match (context.availability, action(input)) {
        (
            AvailabilityView::Unavailable | AvailabilityView::Expired(_),
            Some("availability.set"),
        ) => advance(
            localizer,
            context,
            session,
            AvailabilityState::ChooseDuration {
                observation: expected,
                intent: AvailabilityIntent::Start,
            },
            None,
            None,
            ConversationDisposition::Applied,
        ),
        (
            AvailabilityView::Available(_)
            | AvailabilityView::Stopped(_)
            | AvailabilityView::CapacityPaused(_),
            Some("availability.renew"),
        ) => advance(
            localizer,
            context,
            session,
            AvailabilityState::ChooseDuration {
                observation: expected,
                intent: AvailabilityIntent::Renew,
            },
            None,
            None,
            ConversationDisposition::Applied,
        ),
        (AvailabilityView::Available(_), Some("availability.stop")) => advance(
            localizer,
            context,
            session,
            AvailabilityState::ConfirmStop {
                observation: expected,
            },
            None,
            None,
            ConversationDisposition::Applied,
        ),
        (AvailabilityView::Stopped(_), Some("availability.resume")) => advance(
            localizer,
            context,
            session,
            AvailabilityState::Changed {
                outcome: AvailabilityOutcome::Resumed,
            },
            Some(AvailabilityCommand::Resume { expected }),
            None,
            ConversationDisposition::Applied,
        ),
        _ => unknown(localizer, context, session, state_with(expected)),
    }
}

fn choose_duration(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    expected: AvailabilityObservation,
    intent: AvailabilityIntent,
    input: &UserInput,
) -> TurnPlan {
    let Some(duration) = duration_from_action(action(input)) else {
        return unknown(
            localizer,
            context,
            session,
            AvailabilityState::ChooseDuration {
                observation: expected,
                intent,
            },
        );
    };
    let command = match (intent, context.availability) {
        (
            AvailabilityIntent::Start,
            AvailabilityView::Unavailable | AvailabilityView::Expired(_),
        ) => AvailabilityCommand::Start { duration, expected },
        (
            AvailabilityIntent::Renew,
            AvailabilityView::Available(_)
            | AvailabilityView::Stopped(_)
            | AvailabilityView::CapacityPaused(_),
        ) => AvailabilityCommand::Renew { duration, expected },
        _ => {
            return stale(localizer, context, session);
        }
    };
    let outcome = match intent {
        AvailabilityIntent::Start => AvailabilityOutcome::Started(duration),
        AvailabilityIntent::Renew => AvailabilityOutcome::RenewalScheduled(duration),
    };
    advance(
        localizer,
        context,
        session,
        AvailabilityState::Changed { outcome },
        Some(command),
        None,
        ConversationDisposition::Applied,
    )
}

fn confirm_stop(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    expected: AvailabilityObservation,
    input: &UserInput,
) -> TurnPlan {
    match action(input) {
        Some("availability.stop.confirm")
            if matches!(context.availability, AvailabilityView::Available(_)) =>
        {
            advance(
                localizer,
                context,
                session,
                AvailabilityState::Changed {
                    outcome: AvailabilityOutcome::Stopped,
                },
                Some(AvailabilityCommand::Stop { expected }),
                None,
                ConversationDisposition::Applied,
            )
        }
        Some("availability.stop.cancel") => back_to_status(localizer, context, session),
        _ => unknown(
            localizer,
            context,
            session,
            AvailabilityState::ConfirmStop {
                observation: expected,
            },
        ),
    }
}

fn changed(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    input: &UserInput,
) -> TurnPlan {
    if action(input) == Some("availability.view_status") {
        to_status(
            localizer,
            context,
            session,
            None,
            ConversationDisposition::Applied,
        )
    } else {
        let ConversationState::Availability(state) = &session.state else {
            return to_status(
                localizer,
                context,
                session,
                Some(localizer.text(session.locale, MessageKey::INPUT_UNKNOWN_BODY)),
                ConversationDisposition::Unexpected,
            );
        };
        unknown(localizer, context, session, state.clone())
    }
}

fn to_status(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    prefix: Option<&str>,
    disposition: ConversationDisposition,
) -> TurnPlan {
    advance(
        localizer,
        context,
        session,
        entry_state(context.availability),
        None,
        prefix,
        disposition,
    )
}

fn unknown(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    state: AvailabilityState,
) -> TurnPlan {
    advance(
        localizer,
        context,
        session,
        state,
        None,
        Some(localizer.text(session.locale, MessageKey::INPUT_UNKNOWN_BODY)),
        ConversationDisposition::Unexpected,
    )
}

fn advance(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    next: AvailabilityState,
    command: Option<AvailabilityCommand>,
    prefix: Option<&str>,
    disposition: ConversationDisposition,
) -> TurnPlan {
    let reply = reply(
        localizer,
        session.locale,
        &next,
        context.availability,
        prefix,
    );
    TurnPlan {
        session_change: SessionChange::Advance {
            session_id: session.id,
            expected_version: session.version,
            next: ConversationState::Availability(next),
        },
        locale_change: None,
        business_command: command.map(BusinessCommand::Availability),
        reply,
        disposition,
    }
}

pub(crate) fn reply(
    localizer: &Localizer,
    locale: Locale,
    state: &AvailabilityState,
    view: AvailabilityView,
    prefix: Option<&str>,
) -> ReplySpec {
    let mut reply = match state {
        AvailabilityState::Status { .. } => status_reply(localizer, locale, view),
        AvailabilityState::ChooseDuration { intent, .. } => {
            duration_reply(localizer, locale, *intent)
        }
        AvailabilityState::ConfirmStop { .. } => ReplySpec {
            body: localizer
                .text(locale, MessageKey::AVAILABILITY_STOP_CONFIRM_BODY)
                .to_owned(),
            controls: ReplyControls::Buttons(vec![
                button(
                    "availability.stop.confirm",
                    localizer.text(locale, MessageKey::AVAILABILITY_STOP_CONFIRM_TITLE),
                ),
                button(
                    "availability.stop.cancel",
                    localizer.text(locale, MessageKey::AVAILABILITY_STOP_CANCEL_TITLE),
                ),
            ]),
        },
        AvailabilityState::Changed { outcome } => changed_reply(localizer, locale, *outcome),
    };
    reply.body = join(prefix, &reply.body);
    reply
}

fn status_reply(localizer: &Localizer, locale: Locale, view: AvailabilityView) -> ReplySpec {
    let (body, buttons) = match view {
        AvailabilityView::Ineligible(reason) => {
            let key = match reason {
                AvailabilityIneligibility::ProfessionalRoleRequired => {
                    MessageKey::AVAILABILITY_ROLE_DENIED_BODY
                }
                AvailabilityIneligibility::ProfileApprovalRequired => {
                    MessageKey::AVAILABILITY_APPROVAL_REQUIRED_BODY
                }
                AvailabilityIneligibility::AccountSuspended => {
                    MessageKey::AVAILABILITY_SUSPENDED_BODY
                }
                AvailabilityIneligibility::InvalidTimeZone => {
                    MessageKey::AVAILABILITY_TIME_ZONE_BODY
                }
                AvailabilityIneligibility::TooManyChanges => {
                    MessageKey::AVAILABILITY_THROTTLED_BODY
                }
            };
            (
                localizer.text(locale, key).to_owned(),
                vec![back_button(localizer, locale)],
            )
        }
        AvailabilityView::Unavailable => (
            localizer
                .text(locale, MessageKey::AVAILABILITY_UNAVAILABLE_BODY)
                .to_owned(),
            vec![
                button(
                    "availability.set",
                    localizer.text(locale, MessageKey::AVAILABILITY_SET_TITLE),
                ),
                back_button(localizer, locale),
            ],
        ),
        AvailabilityView::Expired(epoch) => (
            epoch_body(
                localizer,
                locale,
                MessageKey::AVAILABILITY_EXPIRED_STATUS_BODY,
                epoch,
            ),
            vec![
                button(
                    "availability.set",
                    localizer.text(locale, MessageKey::AVAILABILITY_SET_TITLE),
                ),
                back_button(localizer, locale),
            ],
        ),
        AvailabilityView::Available(epoch) => {
            let mut controls = Vec::with_capacity(3);
            if epoch.successor.is_none() {
                controls.push(button(
                    "availability.renew",
                    localizer.text(locale, MessageKey::AVAILABILITY_RENEW_TITLE),
                ));
            }
            controls.push(button(
                "availability.stop",
                localizer.text(locale, MessageKey::AVAILABILITY_STOP_TITLE),
            ));
            controls.push(back_button(localizer, locale));
            (
                epoch_body(
                    localizer,
                    locale,
                    MessageKey::AVAILABILITY_AVAILABLE_BODY,
                    epoch,
                ),
                controls,
            )
        }
        AvailabilityView::Stopped(epoch) => {
            let mut controls = vec![button(
                "availability.resume",
                localizer.text(locale, MessageKey::AVAILABILITY_RESUME_TITLE),
            )];
            if epoch.successor.is_none() {
                controls.push(button(
                    "availability.renew",
                    localizer.text(locale, MessageKey::AVAILABILITY_RENEW_TITLE),
                ));
            }
            controls.push(back_button(localizer, locale));
            (
                epoch_body(
                    localizer,
                    locale,
                    MessageKey::AVAILABILITY_STOPPED_BODY,
                    epoch,
                ),
                controls,
            )
        }
        AvailabilityView::CapacityPaused(epoch) => {
            let mut controls = Vec::with_capacity(2);
            if epoch.successor.is_none() {
                controls.push(button(
                    "availability.renew",
                    localizer.text(locale, MessageKey::AVAILABILITY_RENEW_TITLE),
                ));
            }
            controls.push(back_button(localizer, locale));
            (
                epoch_body(
                    localizer,
                    locale,
                    MessageKey::AVAILABILITY_CAPACITY_PAUSED_BODY,
                    epoch,
                ),
                controls,
            )
        }
    };
    ReplySpec {
        body,
        controls: ReplyControls::Buttons(buttons),
    }
}

fn epoch_body(
    localizer: &Localizer,
    locale: Locale,
    status: MessageKey,
    epoch: crate::AvailabilityEpochView,
) -> String {
    let expiry = format!(
        "{:02}-{:02}-{:04} {:02}:{:02}",
        epoch.local_expiry.day,
        epoch.local_expiry.month,
        epoch.local_expiry.year,
        epoch.local_expiry.hour,
        epoch.local_expiry.minute
    );
    let successor = epoch.successor.map_or_else(
        || {
            localizer
                .text(locale, MessageKey::AVAILABILITY_SUCCESSOR_NONE)
                .to_owned()
        },
        |duration| {
            format!(
                "{}: {}",
                localizer.text(locale, MessageKey::AVAILABILITY_SUCCESSOR_SCHEDULED),
                duration_name(localizer, locale, duration)
            )
        },
    );
    format!(
        "{}\n{}: {}\n{}: {}/{}\n{}",
        localizer.text(locale, status),
        localizer.text(locale, MessageKey::AVAILABILITY_EXPIRY_LABEL),
        expiry,
        localizer.text(locale, MessageKey::AVAILABILITY_CONTACTS_LABEL),
        epoch.contacts_used,
        epoch.contact_limit,
        successor
    )
}

fn duration_reply(localizer: &Localizer, locale: Locale, intent: AvailabilityIntent) -> ReplySpec {
    let body = match intent {
        AvailabilityIntent::Start => MessageKey::AVAILABILITY_START_DURATION_BODY,
        AvailabilityIntent::Renew => MessageKey::AVAILABILITY_RENEW_DURATION_BODY,
    };
    ReplySpec {
        body: localizer.text(locale, body).to_owned(),
        controls: ReplyControls::List {
            open_title: localizer
                .text(locale, MessageKey::AVAILABILITY_DURATION_OPEN_TITLE)
                .to_owned(),
            section_title: localizer
                .text(locale, MessageKey::AVAILABILITY_DURATION_SECTION_TITLE)
                .to_owned(),
            rows: vec![
                duration_row(
                    localizer,
                    locale,
                    "availability.duration.one_hour",
                    AvailabilityDuration::OneHour,
                ),
                duration_row(
                    localizer,
                    locale,
                    "availability.duration.four_hours",
                    AvailabilityDuration::FourHours,
                ),
                duration_row(
                    localizer,
                    locale,
                    "availability.duration.end_of_day",
                    AvailabilityDuration::EndOfLocalDay,
                ),
                ListRowSpec {
                    id: "nav.back".to_owned(),
                    title: localizer.text(locale, MessageKey::NAV_BACK).to_owned(),
                    description: None,
                },
            ],
        },
    }
}

fn changed_reply(localizer: &Localizer, locale: Locale, outcome: AvailabilityOutcome) -> ReplySpec {
    let body = match outcome {
        AvailabilityOutcome::Started(duration) => format!(
            "{} {}. {}",
            localizer.text(locale, MessageKey::AVAILABILITY_CHANGED_STARTED_BODY),
            duration_name(localizer, locale, duration),
            localizer.text(locale, MessageKey::AVAILABILITY_CHANGED_CHECK_BODY)
        ),
        AvailabilityOutcome::Resumed => format!(
            "{} {}",
            localizer.text(locale, MessageKey::AVAILABILITY_CHANGED_RESUMED_BODY),
            localizer.text(locale, MessageKey::AVAILABILITY_CHANGED_CHECK_BODY)
        ),
        AvailabilityOutcome::Stopped => format!(
            "{} {}",
            localizer.text(locale, MessageKey::AVAILABILITY_CHANGED_STOPPED_BODY),
            localizer.text(locale, MessageKey::AVAILABILITY_CHANGED_CHECK_BODY)
        ),
        AvailabilityOutcome::RenewalScheduled(duration) => format!(
            "{} {}. {}",
            localizer.text(locale, MessageKey::AVAILABILITY_CHANGED_RENEWED_BODY),
            duration_name(localizer, locale, duration),
            localizer.text(locale, MessageKey::AVAILABILITY_CHANGED_CHECK_BODY)
        ),
    };
    ReplySpec {
        body,
        controls: ReplyControls::Buttons(vec![
            button(
                "availability.view_status",
                localizer.text(locale, MessageKey::AVAILABILITY_VIEW_STATUS_TITLE),
            ),
            button("nav.menu", localizer.text(locale, MessageKey::NAV_MAIN)),
        ]),
    }
}

fn duration_row(
    localizer: &Localizer,
    locale: Locale,
    id: &str,
    duration: AvailabilityDuration,
) -> ListRowSpec {
    ListRowSpec {
        id: id.to_owned(),
        title: duration_name(localizer, locale, duration).to_owned(),
        description: None,
    }
}

fn duration_name(localizer: &Localizer, locale: Locale, duration: AvailabilityDuration) -> &str {
    localizer.text(
        locale,
        match duration {
            AvailabilityDuration::OneHour => MessageKey::AVAILABILITY_DURATION_ONE_HOUR_TITLE,
            AvailabilityDuration::FourHours => MessageKey::AVAILABILITY_DURATION_FOUR_HOURS_TITLE,
            AvailabilityDuration::EndOfLocalDay => {
                MessageKey::AVAILABILITY_DURATION_END_OF_DAY_TITLE
            }
        },
    )
}

fn back_button(localizer: &Localizer, locale: Locale) -> ButtonSpec {
    button("nav.back", localizer.text(locale, MessageKey::NAV_BACK))
}

fn button(id: &str, title: &str) -> ButtonSpec {
    ButtonSpec {
        id: id.to_owned(),
        title: title.to_owned(),
    }
}

fn state_with(observation: AvailabilityObservation) -> AvailabilityState {
    AvailabilityState::Status { observation }
}

fn duration_from_action(action: Option<&str>) -> Option<AvailabilityDuration> {
    match action {
        Some("availability.duration.one_hour") => Some(AvailabilityDuration::OneHour),
        Some("availability.duration.four_hours") => Some(AvailabilityDuration::FourHours),
        Some("availability.duration.end_of_day") => Some(AvailabilityDuration::EndOfLocalDay),
        _ => None,
    }
}

fn action(input: &UserInput) -> Option<&str> {
    match input {
        UserInput::Action { id, .. } => Some(id.as_str()),
        _ => None,
    }
}

fn join(prefix: Option<&str>, body: &str) -> String {
    prefix.map_or_else(|| body.to_owned(), |prefix| format!("{prefix}\n\n{body}"))
}
