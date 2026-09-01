use crate::{
    AdminCommand, AdminReviewDecision, AdminState, AdminView, BusinessCommand, ConversationContext,
    ConversationDisposition, ConversationState, ReviewReasonCode, SessionChange, SessionSnapshot,
    SessionTerminalStatus, TurnPlan, UserInput,
    render::{ADMIN_PAGE_SIZE, administrator_reply, main_menu},
};
use sahayak_localization::{Localizer, MessageKey};

pub(crate) fn decide(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    state: &AdminState,
    input: &UserInput,
) -> TurnPlan {
    let AdminView::Allowed(allowed) = &context.administrator else {
        return denied(localizer, context, session);
    };
    match state {
        AdminState::Queue { page } => queue(localizer, context, session, *page, input),
        AdminState::Inspect {
            target,
            target_version,
        } => {
            if selected_exists(allowed, target, *target_version) {
                inspect(localizer, context, session, target, *target_version, input)
            } else {
                advance(
                    localizer,
                    context,
                    session,
                    AdminState::Queue { page: 0 },
                    None,
                    Some(localizer.text(session.locale, MessageKey::SELECTION_STALE_BODY)),
                    ConversationDisposition::Stale,
                )
            }
        }
        AdminState::Reason {
            target,
            target_version,
            decision,
        } => reason(
            localizer,
            context,
            session,
            target,
            *target_version,
            *decision,
            input,
        ),
        AdminState::Confirm {
            target,
            target_version,
            decision,
            reason,
        } => confirm(
            localizer,
            context,
            session,
            target,
            *target_version,
            *decision,
            *reason,
            input,
        ),
    }
}

fn queue(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    page: u8,
    input: &UserInput,
) -> TurnPlan {
    let AdminView::Allowed(allowed) = &context.administrator else {
        return denied(localizer, context, session);
    };
    match action(input) {
        Some("admin.queue.next") => {
            let next = page.saturating_add(1).min(crate::MAX_ADMIN_QUEUE_PAGE);
            let start = usize::from(next).saturating_mul(ADMIN_PAGE_SIZE);
            if allowed.pending.get(start).is_some() {
                advance(
                    localizer,
                    context,
                    session,
                    AdminState::Queue { page: next },
                    None,
                    None,
                    ConversationDisposition::Applied,
                )
            } else {
                unknown(localizer, context, session)
            }
        }
        Some("admin.queue.previous") if page > 0 => advance(
            localizer,
            context,
            session,
            AdminState::Queue { page: page - 1 },
            None,
            None,
            ConversationDisposition::Applied,
        ),
        Some(action) => {
            let Some(token) = action.strip_prefix("admin.queue.select:") else {
                return unknown(localizer, context, session);
            };
            let start = usize::from(page).saturating_mul(ADMIN_PAGE_SIZE);
            let Some(item) = allowed
                .pending
                .iter()
                .skip(start)
                .take(ADMIN_PAGE_SIZE)
                .find(|item| item.target.as_str() == token)
            else {
                return unknown(localizer, context, session);
            };
            advance(
                localizer,
                context,
                session,
                AdminState::Inspect {
                    target: item.target.clone(),
                    target_version: item.version,
                },
                None,
                None,
                ConversationDisposition::Applied,
            )
        }
        None => unknown(localizer, context, session),
    }
}

fn inspect(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    target: &crate::OpaqueTargetToken,
    target_version: i64,
    input: &UserInput,
) -> TurnPlan {
    let next = match action(input) {
        Some("admin.decision.approve") => Some(AdminState::Confirm {
            target: target.clone(),
            target_version,
            decision: AdminReviewDecision::Approve,
            reason: None,
        }),
        Some("admin.decision.changes") => Some(AdminState::Reason {
            target: target.clone(),
            target_version,
            decision: AdminReviewDecision::ChangesRequested,
        }),
        Some("admin.decision.reject") => Some(AdminState::Reason {
            target: target.clone(),
            target_version,
            decision: AdminReviewDecision::Reject,
        }),
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

fn reason(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    target: &crate::OpaqueTargetToken,
    target_version: i64,
    decision: AdminReviewDecision,
    input: &UserInput,
) -> TurnPlan {
    let reason = match action(input) {
        Some("admin.reason.incomplete") => Some(ReviewReasonCode::IncompleteDetails),
        Some("admin.reason.mismatch") => Some(ReviewReasonCode::ServiceMismatch),
        Some("admin.reason.photo") => Some(ReviewReasonCode::PhotoConcern),
        Some("admin.reason.policy") => Some(ReviewReasonCode::PolicyViolation),
        _ => None,
    };
    reason.map_or_else(
        || unknown(localizer, context, session),
        |reason| {
            advance(
                localizer,
                context,
                session,
                AdminState::Confirm {
                    target: target.clone(),
                    target_version,
                    decision,
                    reason: Some(reason),
                },
                None,
                None,
                ConversationDisposition::Applied,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn confirm(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    target: &crate::OpaqueTargetToken,
    target_version: i64,
    decision: AdminReviewDecision,
    reason: Option<ReviewReasonCode>,
    input: &UserInput,
) -> TurnPlan {
    match action(input) {
        Some("admin.confirm.yes") => TurnPlan {
            session_change: SessionChange::Advance {
                session_id: session.id,
                expected_version: session.version,
                next: ConversationState::Administrator(AdminState::Queue { page: 0 }),
            },
            locale_change: None,
            business_command: Some(BusinessCommand::Administrator(
                AdminCommand::ReviewProfile {
                    target: target.clone(),
                    expected_version: target_version,
                    decision,
                    reason,
                },
            )),
            reply: crate::ReplySpec {
                body: localizer
                    .text(session.locale, MessageKey::ADMIN_DONE_BODY)
                    .to_owned(),
                controls: crate::ReplyControls::None,
            },
            disposition: ConversationDisposition::Applied,
        },
        Some("admin.confirm.no") => advance(
            localizer,
            context,
            session,
            AdminState::Inspect {
                target: target.clone(),
                target_version,
            },
            None,
            None,
            ConversationDisposition::Applied,
        ),
        _ => unknown(localizer, context, session),
    }
}

fn denied(
    localizer: &Localizer,
    _context: &ConversationContext,
    session: &SessionSnapshot,
) -> TurnPlan {
    TurnPlan {
        session_change: SessionChange::Replace {
            session_id: session.id,
            expected_version: session.version,
            next: ConversationState::MainShow,
            locale: session.locale,
            terminal_status: SessionTerminalStatus::Abandoned,
            terminal_reason: "administrator_denied",
        },
        locale_change: None,
        business_command: None,
        reply: main_menu(
            localizer,
            session.locale,
            Some(localizer.text(session.locale, MessageKey::ADMIN_DENIED_BODY)),
        ),
        disposition: ConversationDisposition::Unexpected,
    }
}

fn advance(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
    next: AdminState,
    command: Option<AdminCommand>,
    prefix: Option<&str>,
    disposition: ConversationDisposition,
) -> TurnPlan {
    let reply = administrator_reply(
        localizer,
        session.locale,
        &next,
        &context.administrator,
        prefix,
    );
    TurnPlan {
        session_change: SessionChange::Advance {
            session_id: session.id,
            expected_version: session.version,
            next: ConversationState::Administrator(next),
        },
        locale_change: None,
        business_command: command.map(BusinessCommand::Administrator),
        reply,
        disposition,
    }
}

fn unknown(
    localizer: &Localizer,
    context: &ConversationContext,
    session: &SessionSnapshot,
) -> TurnPlan {
    let ConversationState::Administrator(state) = &session.state else {
        return denied(localizer, context, session);
    };
    advance(
        localizer,
        context,
        session,
        state.clone(),
        None,
        Some(localizer.text(session.locale, MessageKey::INPUT_UNKNOWN_BODY)),
        ConversationDisposition::Unexpected,
    )
}

fn selected_exists(
    allowed: &crate::AllowedAdminView,
    target: &crate::OpaqueTargetToken,
    version: i64,
) -> bool {
    allowed
        .selected
        .as_ref()
        .is_some_and(|item| item.target == *target && item.version == version)
        || allowed
            .pending
            .iter()
            .any(|item| item.target == *target && item.version == version)
}

fn action(input: &UserInput) -> Option<&str> {
    match input {
        UserInput::Action { id, .. } => Some(id.as_str()),
        _ => None,
    }
}
