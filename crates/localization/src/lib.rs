//! Validated English, Hindi, and Marathi conversation catalogs.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use thiserror::Error;

const EN_IN: &str = include_str!("../../../resources/localization/en-IN.json");
const HI_IN: &str = include_str!("../../../resources/localization/hi-IN.json");
const MR_IN: &str = include_str!("../../../resources/localization/mr-IN.json");

/// Supported interface locale for the initial India pilot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Locale {
    /// English as used in India.
    #[serde(rename = "en-IN")]
    EnIn,
    /// Hindi in Devanagari.
    #[serde(rename = "hi-IN")]
    HiIn,
    /// Marathi in Devanagari.
    #[serde(rename = "mr-IN")]
    MrIn,
}

impl Locale {
    /// Every locale required by continuous integration.
    pub const ALL: [Self; 3] = [Self::EnIn, Self::HiIn, Self::MrIn];

    /// Returns the stable BCP-47 account value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnIn => "en-IN",
            Self::HiIn => "hi-IN",
            Self::MrIn => "mr-IN",
        }
    }

    /// Parses supported BCP-47 and base-language aliases.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "en" | "en-IN" => Some(Self::EnIn),
            "hi" | "hi-IN" => Some(Self::HiIn),
            "mr" | "mr-IN" => Some(Self::MrIn),
            _ => None,
        }
    }

    /// Meta template language code for this locale.
    #[must_use]
    pub const fn meta_template_code(self) -> &'static str {
        match self {
            Self::EnIn => "en_IN",
            Self::HiIn => "hi",
            Self::MrIn => "mr",
        }
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable message key shared by every locale catalog.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageKey(&'static str);

impl MessageKey {
    pub const LANGUAGE_SELECT_BODY: Self = Self("language.select.body");
    pub const LANGUAGE_OPTION_EN: Self = Self("language.option.en.title");
    pub const LANGUAGE_OPTION_HI: Self = Self("language.option.hi.title");
    pub const LANGUAGE_OPTION_MR: Self = Self("language.option.mr.title");
    pub const LANGUAGE_CONFIRM_BODY: Self = Self("language.confirm.body");
    pub const LANGUAGE_CONFIRM_YES: Self = Self("language.confirm.yes.title");
    pub const LANGUAGE_CONFIRM_CHANGE: Self = Self("language.confirm.change.title");
    pub const LANGUAGE_SAVED_BODY: Self = Self("language.saved.body");
    pub const LANGUAGE_CHANGE_BODY: Self = Self("language.change.body");
    pub const MAIN_BODY: Self = Self("main.body");
    pub const MAIN_FIND: Self = Self("main.find.title");
    pub const MAIN_OFFER: Self = Self("main.offer.title");
    pub const MAIN_MORE: Self = Self("main.more.title");
    pub const MORE_BODY: Self = Self("more.body");
    pub const MORE_OPEN: Self = Self("more.open.title");
    pub const MORE_AVAILABILITY_TITLE: Self = Self("more.availability.title");
    pub const MORE_AVAILABILITY_DESC: Self = Self("more.availability.desc");
    pub const MORE_REQUESTS_TITLE: Self = Self("more.requests.title");
    pub const MORE_REQUESTS_DESC: Self = Self("more.requests.desc");
    pub const MORE_CONTACTS_TITLE: Self = Self("more.contacts.title");
    pub const MORE_CONTACTS_DESC: Self = Self("more.contacts.desc");
    pub const MORE_ACCOUNT_TITLE: Self = Self("more.account.title");
    pub const MORE_ACCOUNT_DESC: Self = Self("more.account.desc");
    pub const MORE_HELP_TITLE: Self = Self("more.help.title");
    pub const MORE_HELP_DESC: Self = Self("more.help.desc");
    pub const MORE_LANGUAGE_TITLE: Self = Self("more.language.title");
    pub const MORE_LANGUAGE_DESC: Self = Self("more.language.desc");
    pub const MORE_ADMIN_TITLE: Self = Self("more.admin.title");
    pub const MORE_ADMIN_DESC: Self = Self("more.admin.desc");
    pub const NAV_BACK: Self = Self("nav.back.title");
    pub const NAV_CANCEL: Self = Self("nav.cancel.title");
    pub const NAV_MAIN: Self = Self("nav.main.title");
    pub const NAV_BACK_AT_ROOT_BODY: Self = Self("nav.back.at_root.body");
    pub const CANCEL_CONFIRM_BODY: Self = Self("cancel.confirm.body");
    pub const CANCEL_YES: Self = Self("cancel.yes.title");
    pub const CANCEL_NO: Self = Self("cancel.no.title");
    pub const CANCEL_DONE_BODY: Self = Self("cancel.done.body");
    pub const CANCEL_NONE_BODY: Self = Self("cancel.none.body");
    pub const HELP_MENU_BODY: Self = Self("help.menu.body");
    pub const HELP_MENU_OPEN: Self = Self("help.menu.open.title");
    pub const HELP_ABOUT_TITLE: Self = Self("help.about.title");
    pub const HELP_ABOUT_DESC: Self = Self("help.about.desc");
    pub const HELP_ABOUT_BODY: Self = Self("help.about.body");
    pub const HELP_REPORT_TITLE: Self = Self("help.report.title");
    pub const HELP_REPORT_DESC: Self = Self("help.report.desc");
    pub const HELP_EMERGENCY_TITLE: Self = Self("help.emergency.title");
    pub const HELP_EMERGENCY_DESC: Self = Self("help.emergency.desc");
    pub const HELP_EMERGENCY_BODY: Self = Self("help.emergency.body");
    pub const INPUT_UNKNOWN_BODY: Self = Self("input.unknown.body");
    pub const SELECTION_STALE_BODY: Self = Self("selection.stale.body");
    pub const SESSION_EXPIRED_BODY: Self = Self("session.expired.body");
    pub const FUTURE_GENERIC_BODY: Self = Self("future.generic.body");
    pub const FUTURE_OFFER_BODY: Self = Self("future.offer.body");
    pub const AVAILABILITY_ROLE_DENIED_BODY: Self = Self("availability.error.role.body");
    pub const AVAILABILITY_APPROVAL_REQUIRED_BODY: Self = Self("availability.error.approval.body");
    pub const AVAILABILITY_SUSPENDED_BODY: Self = Self("availability.error.account.body");
    pub const AVAILABILITY_TIME_ZONE_BODY: Self = Self("availability.error.time_zone.body");
    pub const AVAILABILITY_THROTTLED_BODY: Self = Self("availability.error.throttled.body");
    pub const AVAILABILITY_UNAVAILABLE_BODY: Self = Self("availability.status.unavailable.body");
    pub const AVAILABILITY_EXPIRED_STATUS_BODY: Self = Self("availability.status.expired.body");
    pub const AVAILABILITY_AVAILABLE_BODY: Self = Self("availability.status.available.body");
    pub const AVAILABILITY_STOPPED_BODY: Self = Self("availability.status.stopped.body");
    pub const AVAILABILITY_CAPACITY_PAUSED_BODY: Self =
        Self("availability.status.paused_limit.body");
    pub const AVAILABILITY_SUCCESSOR_NONE: Self = Self("availability.successor.none");
    pub const AVAILABILITY_SUCCESSOR_SCHEDULED: Self = Self("availability.successor.scheduled");
    pub const AVAILABILITY_EXPIRY_LABEL: Self = Self("availability.status.until.label");
    pub const AVAILABILITY_CONTACTS_LABEL: Self = Self("availability.status.contacts.label");
    pub const AVAILABILITY_SET_TITLE: Self = Self("availability.set.title");
    pub const AVAILABILITY_RENEW_TITLE: Self = Self("availability.renew.title");
    pub const AVAILABILITY_STOP_TITLE: Self = Self("availability.stop.title");
    pub const AVAILABILITY_RESUME_TITLE: Self = Self("availability.resume.title");
    pub const AVAILABILITY_VIEW_STATUS_TITLE: Self = Self("availability.view_status.title");
    pub const AVAILABILITY_START_DURATION_BODY: Self = Self("availability.duration.start.body");
    pub const AVAILABILITY_RENEW_DURATION_BODY: Self = Self("availability.duration.renew.body");
    pub const AVAILABILITY_DURATION_OPEN_TITLE: Self = Self("availability.duration.open.title");
    pub const AVAILABILITY_DURATION_SECTION_TITLE: Self =
        Self("availability.duration.section.title");
    pub const AVAILABILITY_DURATION_ONE_HOUR_TITLE: Self =
        Self("availability.duration.one_hour.title");
    pub const AVAILABILITY_DURATION_FOUR_HOURS_TITLE: Self =
        Self("availability.duration.four_hours.title");
    pub const AVAILABILITY_DURATION_END_OF_DAY_TITLE: Self =
        Self("availability.duration.end_of_day.title");
    pub const AVAILABILITY_STOP_CONFIRM_BODY: Self = Self("availability.stop.confirm.body");
    pub const AVAILABILITY_STOP_CONFIRM_TITLE: Self = Self("availability.stop.confirm.title");
    pub const AVAILABILITY_STOP_CANCEL_TITLE: Self = Self("availability.stop.cancel.title");
    pub const AVAILABILITY_CHANGED_STARTED_BODY: Self = Self("availability.changed.started.body");
    pub const AVAILABILITY_CHANGED_RESUMED_BODY: Self = Self("availability.changed.resumed.body");
    pub const AVAILABILITY_CHANGED_STOPPED_BODY: Self = Self("availability.changed.stopped.body");
    pub const AVAILABILITY_CHANGED_RENEWED_BODY: Self = Self("availability.changed.renewed.body");
    pub const AVAILABILITY_CHANGED_CHECK_BODY: Self = Self("availability.changed.check.body");
    pub const AVAILABILITY_REMINDER_BODY: Self = Self("availability.notification.reminder.body");
    pub const AVAILABILITY_EXPIRED_BODY: Self = Self("availability.notification.expired.body");
    pub const AVAILABILITY_LIMIT_BODY: Self = Self("availability.notification.limit.body");
    pub const DISCOVERY_CATEGORY_BODY: Self = Self("discovery.category.body");
    pub const DISCOVERY_CATEGORY_PLUMBER: Self = Self("discovery.category.plumber");
    pub const DISCOVERY_CATEGORY_ELECTRICIAN: Self = Self("discovery.category.electrician");
    pub const DISCOVERY_LOCATION_BODY: Self = Self("discovery.location.body");
    pub const DISCOVERY_TIME_BODY: Self = Self("discovery.time.body");
    pub const DISCOVERY_TIME_NOW: Self = Self("discovery.time.now");
    pub const DISCOVERY_TIME_TODAY: Self = Self("discovery.time.today");
    pub const DISCOVERY_TIME_FLEXIBLE: Self = Self("discovery.time.flexible");
    pub const DISCOVERY_ISSUE_PLUMBER_BODY: Self = Self("discovery.issue.plumber.body");
    pub const DISCOVERY_ISSUE_ELECTRICIAN_BODY: Self = Self("discovery.issue.electrician.body");
    pub const DISCOVERY_ISSUE_OPEN: Self = Self("discovery.issue.open");
    pub const DISCOVERY_ISSUE_LEAK: Self = Self("discovery.issue.leak");
    pub const DISCOVERY_ISSUE_BLOCKAGE: Self = Self("discovery.issue.blockage");
    pub const DISCOVERY_ISSUE_INSTALLATION: Self = Self("discovery.issue.installation");
    pub const DISCOVERY_ISSUE_OUTAGE: Self = Self("discovery.issue.outage");
    pub const DISCOVERY_ISSUE_WIRING: Self = Self("discovery.issue.wiring");
    pub const DISCOVERY_ISSUE_OTHER: Self = Self("discovery.issue.other");
    pub const DISCOVERY_SEARCH_COMPLETE_BODY: Self = Self("discovery.search.complete.body");
    pub const DISCOVERY_VIEW_RESULTS: Self = Self("discovery.view_results");
    pub const DISCOVERY_RESULTS_BODY: Self = Self("discovery.results.body");
    pub const DISCOVERY_RESULTS_OPEN: Self = Self("discovery.results.open");
    pub const DISCOVERY_RESULTS_SECTION: Self = Self("discovery.results.section");
    pub const DISCOVERY_NO_RESULTS_BODY: Self = Self("discovery.no_results.body");
    pub const DISCOVERY_EXPAND_TITLE: Self = Self("discovery.expand.title");
    pub const DISCOVERY_EXPAND_DESC: Self = Self("discovery.expand.description");
    pub const DISCOVERY_SHOW_MORE_TITLE: Self = Self("discovery.show_more.title");
    pub const DISCOVERY_SHOW_MORE_DESC: Self = Self("discovery.show_more.description");
    pub const DISCOVERY_DISTANCE_UNDER_ONE: Self = Self("discovery.distance.under_one");
    pub const DISCOVERY_DISTANCE_UNDER_FIVE: Self = Self("discovery.distance.under_five");
    pub const DISCOVERY_DISTANCE_UNDER_TEN: Self = Self("discovery.distance.under_ten");
    pub const DISCOVERY_DISTANCE_FARTHER: Self = Self("discovery.distance.farther");
    pub const DISCOVERY_AVAILABLE_RECENT: Self = Self("discovery.availability.recent");
    pub const DISCOVERY_AVAILABLE_NOW: Self = Self("discovery.availability.now");
    pub const DISCOVERY_IDENTITY_CHECKED: Self = Self("discovery.identity_checked");
    pub const DISCOVERY_DIRECT_LABEL: Self = Self("discovery.contact.direct");
    pub const DISCOVERY_APPROVAL_LABEL: Self = Self("discovery.contact.approval");
    pub const DISCOVERY_CONFIRM_DIRECT_BODY: Self = Self("discovery.confirm.direct.body");
    pub const DISCOVERY_CONFIRM_APPROVAL_BODY: Self = Self("discovery.confirm.approval.body");
    pub const DISCOVERY_CONFIRM_YES: Self = Self("discovery.confirm.yes");
    pub const DISCOVERY_CONFIRM_CANCEL: Self = Self("discovery.confirm.cancel");
    pub const DISCOVERY_DIRECT_PROCESSING_BODY: Self = Self("discovery.direct.processing.body");
    pub const DISCOVERY_REQUEST_SENT_BODY: Self = Self("discovery.request.sent.body");
    pub const DISCOVERY_WAITING_BODY: Self = Self("discovery.waiting.body");
    pub const DISCOVERY_REQUEST_CANCEL_TITLE: Self = Self("discovery.request.cancel.title");
    pub const DISCOVERY_REQUEST_CANCELLED_BODY: Self = Self("discovery.request.cancelled.body");
    pub const RECENT_CONTACTS_BODY: Self = Self("recent.contacts.body");
    pub const RECENT_CONTACTS_EMPTY_BODY: Self = Self("recent.contacts.empty.body");
    pub const RECENT_CONTACTS_OPEN: Self = Self("recent.contacts.open");
    pub const RECENT_CONTACT_PROCESSING_BODY: Self = Self("recent.contact.processing.body");
    pub const REQUESTS_LIST_BODY: Self = Self("requests.list.body");
    pub const REQUESTS_EMPTY_BODY: Self = Self("requests.empty.body");
    pub const REQUESTS_OPEN_TITLE: Self = Self("requests.open.title");
    pub const REQUESTS_INSPECT_BODY: Self = Self("requests.inspect.body");
    pub const REQUESTS_STALE_BODY: Self = Self("requests.stale.body");
    pub const REQUESTS_ACCEPT_TITLE: Self = Self("requests.accept.title");
    pub const REQUESTS_DECLINE_TITLE: Self = Self("requests.decline.title");
    pub const REQUESTS_ACCEPT_CONFIRM_BODY: Self = Self("requests.accept.confirm.body");
    pub const REQUESTS_DECLINE_CONFIRM_BODY: Self = Self("requests.decline.confirm.body");
    pub const REQUESTS_CONFIRM_TITLE: Self = Self("requests.confirm.title");
    pub const REQUESTS_CANCEL_TITLE: Self = Self("requests.cancel.title");
    pub const REQUESTS_ACCEPTED_BODY: Self = Self("requests.accepted.body");
    pub const REQUESTS_DECLINED_BODY: Self = Self("requests.declined.body");
    pub const CONNECTION_CONTACT_BODY: Self = Self("connection.contact.body");
    pub const CONNECTION_CALL_LABEL: Self = Self("connection.call.label");
    pub const CONNECTION_WHATSAPP_LABEL: Self = Self("connection.whatsapp.label");
    pub const CONNECTION_DIRECT_NOTIFY_BODY: Self = Self("connection.direct.notify.body");
    pub const CONNECTION_REQUEST_NOTIFY_BODY: Self = Self("connection.request.notify.body");
    pub const CONNECTION_CUSTOMER_LIMIT_BODY: Self = Self("connection.customer_limit.body");
    pub const CONNECTION_CAPACITY_BODY: Self = Self("connection.capacity.body");
    pub const FUTURE_ACCOUNT_BODY: Self = Self("future.account.body");
    pub const BILLING_FREE_BODY: Self = Self("billing.free.body");
    pub const BILLING_PAYMENT_REQUIRED_BODY: Self = Self("billing.payment_required.body");
    pub const BILLING_PENDING_BODY: Self = Self("billing.pending.body");
    pub const BILLING_ACTIVE_BODY: Self = Self("billing.active.body");
    pub const BILLING_GRACE_BODY: Self = Self("billing.grace.body");
    pub const BILLING_EXPIRED_BODY: Self = Self("billing.expired.body");
    pub const BILLING_WAIVED_BODY: Self = Self("billing.waived.body");
    pub const TRUST_LIST_BODY: Self = Self("trust.list.body");
    pub const TRUST_EMPTY_BODY: Self = Self("trust.empty.body");
    pub const TRUST_LIST_TITLE: Self = Self("trust.list.title");
    pub const TRUST_CUSTOMER_TITLE: Self = Self("trust.customer.title");
    pub const TRUST_ACTIONS_BODY: Self = Self("trust.actions.body");
    pub const TRUST_REVIEW_TITLE: Self = Self("trust.review.title");
    pub const TRUST_REPORT_TITLE: Self = Self("trust.report.title");
    pub const TRUST_BLOCK_TITLE: Self = Self("trust.block.title");
    pub const TRUST_NO_BLOCK_TITLE: Self = Self("trust.no_block.title");
    pub const TRUST_CONFIRM_TITLE: Self = Self("trust.confirm.title");
    pub const TRUST_SKIP_TITLE: Self = Self("trust.skip.title");
    pub const TRUST_RATING_TITLE: Self = Self("trust.rating.title");
    pub const TRUST_REVIEW_CONNECTION_BODY: Self = Self("trust.review.connection.body");
    pub const TRUST_REVIEW_RESPONSIVENESS_BODY: Self = Self("trust.review.responsiveness.body");
    pub const TRUST_REVIEW_COMPLETION_BODY: Self = Self("trust.review.completion.body");
    pub const TRUST_REVIEW_FEEDBACK_BODY: Self = Self("trust.review.feedback.body");
    pub const TRUST_REVIEW_SUBMITTED_BODY: Self = Self("trust.review.submitted.body");
    pub const TRUST_REPORT_CATEGORY_BODY: Self = Self("trust.report.category.body");
    pub const TRUST_REPORT_BLOCK_BODY: Self = Self("trust.report.block.body");
    pub const TRUST_REPORT_DESCRIPTION_BODY: Self = Self("trust.report.description.body");
    pub const TRUST_REPORT_SUBMITTED_BODY: Self = Self("trust.report.submitted.body");
    pub const TRUST_BLOCK_CONFIRM_BODY: Self = Self("trust.block.confirm.body");
    pub const TRUST_BLOCKED_BODY: Self = Self("trust.blocked.body");
    pub const TRUST_STALE_BODY: Self = Self("trust.stale.body");
    pub const TRUST_CATEGORY_SPAM: Self = Self("trust.category.spam");
    pub const TRUST_CATEGORY_HARASSMENT: Self = Self("trust.category.harassment");
    pub const TRUST_CATEGORY_FRAUD: Self = Self("trust.category.fraud");
    pub const TRUST_CATEGORY_UNSAFE: Self = Self("trust.category.unsafe");
    pub const TRUST_CATEGORY_IDENTITY: Self = Self("trust.category.identity");
    pub const TRUST_CATEGORY_NO_SHOW: Self = Self("trust.category.no_show");
    pub const TRUST_CATEGORY_OTHER: Self = Self("trust.category.other");
    pub const SAFETY_ADMIN_QUEUE_TITLE: Self = Self("safety.admin.queue.title");
    pub const SAFETY_ADMIN_QUEUE_BODY: Self = Self("safety.admin.queue.body");
    pub const SAFETY_ADMIN_EMPTY_BODY: Self = Self("safety.admin.empty.body");
    pub const SAFETY_ADMIN_INSPECT_BODY: Self = Self("safety.admin.inspect.body");
    pub const SAFETY_ADMIN_ACTION_TITLE: Self = Self("safety.admin.action.title");
    pub const SAFETY_ADMIN_NO_ACTION: Self = Self("safety.admin.no_action");
    pub const SAFETY_ADMIN_WARNING: Self = Self("safety.admin.warning");
    pub const SAFETY_ADMIN_SUSPEND: Self = Self("safety.admin.suspend");
    pub const SAFETY_ADMIN_REMOVE: Self = Self("safety.admin.remove");
    pub const SAFETY_ADMIN_CONFIRM_BODY: Self = Self("safety.admin.confirm.body");
    pub const SAFETY_ADMIN_RESOLVED_BODY: Self = Self("safety.admin.resolved.body");
    pub const SAFETY_RESOLUTION_NOTICE_BODY: Self = Self("safety.resolution.notice.body");
    pub const SAFETY_REPORTER_RESOLUTION_BODY: Self = Self("safety.reporter.resolution.body");
    pub const FUTURE_REPORT_BODY: Self = Self("future.report.body");
    pub const PRO_NAME_BODY: Self = Self("professional.name.body");
    pub const PRO_NAME_INVALID_BODY: Self = Self("professional.name.invalid.body");
    pub const PRO_NAME_CONFIRM_BODY: Self = Self("professional.name.confirm.body");
    pub const PRO_NAME_USE_TITLE: Self = Self("professional.name.use.title");
    pub const PRO_NAME_CHANGE_TITLE: Self = Self("professional.name.change.title");
    pub const PRO_CATEGORIES_BODY: Self = Self("professional.categories.body");
    pub const PRO_CATEGORY_PLUMBER_TITLE: Self = Self("professional.category.plumber.title");
    pub const PRO_CATEGORY_ELECTRICIAN_TITLE: Self =
        Self("professional.category.electrician.title");
    pub const PRO_SELECTION_DONE_TITLE: Self = Self("professional.selection.done.title");
    pub const PRO_SELECTION_REQUIRED_BODY: Self = Self("professional.selection.required.body");
    pub const PRO_SKILLS_PLUMBER_BODY: Self = Self("professional.skills.plumber.body");
    pub const PRO_SKILLS_ELECTRICIAN_BODY: Self = Self("professional.skills.electrician.body");
    pub const PRO_SKILL_LEAK_TITLE: Self = Self("professional.skill.leak.title");
    pub const PRO_SKILL_FIXTURE_TITLE: Self = Self("professional.skill.fixture.title");
    pub const PRO_SKILL_DRAIN_TITLE: Self = Self("professional.skill.drain.title");
    pub const PRO_SKILL_WIRING_TITLE: Self = Self("professional.skill.wiring.title");
    pub const PRO_SKILL_SWITCH_TITLE: Self = Self("professional.skill.switch.title");
    pub const PRO_SKILL_FAN_TITLE: Self = Self("professional.skill.fan.title");
    pub const PRO_AREA_BODY: Self = Self("professional.area.body");
    pub const PRO_AREA_TRAVEL_TITLE: Self = Self("professional.area.travel.title");
    pub const PRO_AREA_VISITS_TITLE: Self = Self("professional.area.visits.title");
    pub const PRO_AREA_BOTH_TITLE: Self = Self("professional.area.both.title");
    pub const PRO_LOCATION_BODY: Self = Self("professional.location.body");
    pub const PRO_RADIUS_BODY: Self = Self("professional.radius.body");
    pub const PRO_RADIUS_OPEN_TITLE: Self = Self("professional.radius.open.title");
    pub const PRO_RADIUS_2_TITLE: Self = Self("professional.radius.2.title");
    pub const PRO_RADIUS_5_TITLE: Self = Self("professional.radius.5.title");
    pub const PRO_RADIUS_10_TITLE: Self = Self("professional.radius.10.title");
    pub const PRO_RADIUS_25_TITLE: Self = Self("professional.radius.25.title");
    pub const PRO_LANGUAGES_BODY: Self = Self("professional.languages.body");
    pub const PRO_LANGUAGES_OPEN_TITLE: Self = Self("professional.languages.open.title");
    pub const PRO_CONTACT_PLUMBER_BODY: Self = Self("professional.contact.plumber.body");
    pub const PRO_CONTACT_ELECTRICIAN_BODY: Self = Self("professional.contact.electrician.body");
    pub const PRO_CONTACT_DIRECT_TITLE: Self = Self("professional.contact.direct.title");
    pub const PRO_CONTACT_APPROVAL_TITLE: Self = Self("professional.contact.approval.title");
    pub const PRO_LIMIT_BODY: Self = Self("professional.limit.body");
    pub const PRO_LIMIT_OPEN_TITLE: Self = Self("professional.limit.open.title");
    pub const PRO_LIMIT_1_TITLE: Self = Self("professional.limit.1.title");
    pub const PRO_LIMIT_3_TITLE: Self = Self("professional.limit.3.title");
    pub const PRO_LIMIT_5_TITLE: Self = Self("professional.limit.5.title");
    pub const PRO_LIMIT_10_TITLE: Self = Self("professional.limit.10.title");
    pub const PRO_PHOTO_BODY: Self = Self("professional.photo.body");
    pub const PRO_PHOTO_SKIP_TITLE: Self = Self("professional.photo.skip.title");
    pub const PRO_PHOTO_REMOVE_TITLE: Self = Self("professional.photo.remove.title");
    pub const PRO_DISCLOSURE_BODY: Self = Self("professional.disclosure.body");
    pub const PRO_CONTINUE_TITLE: Self = Self("professional.continue.title");
    pub const PRO_CONSENT_BODY: Self = Self("professional.consent.body");
    pub const PRO_CONSENT_ACCEPT_TITLE: Self = Self("professional.consent.accept.title");
    pub const PRO_SUMMARY_BODY: Self = Self("professional.summary.body");
    pub const PRO_SUMMARY_DISPLAY_LABEL: Self = Self("professional.summary.display.label");
    pub const PRO_SUMMARY_CATEGORIES_LABEL: Self = Self("professional.summary.categories.label");
    pub const PRO_SUMMARY_SKILLS_LABEL: Self = Self("professional.summary.skills.label");
    pub const PRO_SUMMARY_AREA_LABEL: Self = Self("professional.summary.area.label");
    pub const PRO_SUMMARY_RADIUS_LABEL: Self = Self("professional.summary.radius.label");
    pub const PRO_SUMMARY_LANGUAGES_LABEL: Self = Self("professional.summary.languages.label");
    pub const PRO_SUMMARY_CONTACT_LABEL: Self = Self("professional.summary.contact.label");
    pub const PRO_SUMMARY_LIMIT_LABEL: Self = Self("professional.summary.limit.label");
    pub const PRO_SUMMARY_PHOTO_LABEL: Self = Self("professional.summary.photo.label");
    pub const PRO_SUMMARY_IDENTITY_LABEL: Self = Self("professional.summary.identity.label");
    pub const PRO_SUMMARY_SUBMIT_TITLE: Self = Self("professional.summary.submit.title");
    pub const PRO_SUMMARY_EDIT_TITLE: Self = Self("professional.summary.edit.title");
    pub const PRO_VALUE_NONE: Self = Self("professional.value.none");
    pub const PRO_VALUE_PHOTO_PRESENT: Self = Self("professional.value.photo_present");
    pub const PRO_VALUE_PHOTO_NONE: Self = Self("professional.value.photo_none");
    pub const PRO_VALUE_IDENTITY_CHECKED: Self = Self("professional.value.identity_checked");
    pub const PRO_VALUE_IDENTITY_NOT_CHECKED: Self =
        Self("professional.value.identity_not_checked");
    pub const PRO_VALUE_CONTACT_DIRECT: Self = Self("professional.value.contact_direct");
    pub const PRO_VALUE_CONTACT_APPROVAL: Self = Self("professional.value.contact_approval");
    pub const PRO_VALUE_AREA_TRAVEL: Self = Self("professional.value.area_travel");
    pub const PRO_VALUE_AREA_VISITS: Self = Self("professional.value.area_visits");
    pub const PRO_VALUE_AREA_BOTH: Self = Self("professional.value.area_both");
    pub const PRO_SUBMITTED_BODY: Self = Self("professional.submitted.body");
    pub const PRO_STATUS_DRAFT_BODY: Self = Self("professional.status.draft.body");
    pub const PRO_STATUS_PENDING_BODY: Self = Self("professional.status.pending.body");
    pub const PRO_STATUS_CHANGES_BODY: Self = Self("professional.status.changes.body");
    pub const PRO_STATUS_APPROVED_BODY: Self = Self("professional.status.approved.body");
    pub const PRO_STATUS_REJECTED_BODY: Self = Self("professional.status.rejected.body");
    pub const PRO_STATUS_HIDDEN_BODY: Self = Self("professional.status.hidden.body");
    pub const PRO_STATUS_RESUME_TITLE: Self = Self("professional.status.resume.title");
    pub const PRO_STATUS_EDIT_TITLE: Self = Self("professional.status.edit.title");
    pub const PRO_EDIT_BODY: Self = Self("professional.edit.body");
    pub const PRO_EDIT_OPEN_TITLE: Self = Self("professional.edit.open.title");
    pub const PRO_FIELD_DISPLAY_NAME_TITLE: Self = Self("professional.field.display_name.title");
    pub const PRO_FIELD_SERVICES_TITLE: Self = Self("professional.field.services.title");
    pub const PRO_FIELD_AREA_TITLE: Self = Self("professional.field.area.title");
    pub const PRO_FIELD_LANGUAGES_TITLE: Self = Self("professional.field.languages.title");
    pub const PRO_FIELD_CONTACT_TITLE: Self = Self("professional.field.contact.title");
    pub const PRO_FIELD_PHOTO_TITLE: Self = Self("professional.field.photo.title");
    pub const ADMIN_DENIED_BODY: Self = Self("admin.denied.body");
    pub const ADMIN_QUEUE_BODY: Self = Self("admin.queue.body");
    pub const ADMIN_QUEUE_EMPTY_BODY: Self = Self("admin.queue.empty.body");
    pub const ADMIN_QUEUE_OPEN_TITLE: Self = Self("admin.queue.open.title");
    pub const ADMIN_QUEUE_SECTION_TITLE: Self = Self("admin.queue.section.title");
    pub const ADMIN_QUEUE_NEXT_TITLE: Self = Self("admin.queue.next.title");
    pub const ADMIN_QUEUE_PREVIOUS_TITLE: Self = Self("admin.queue.previous.title");
    pub const ADMIN_INSPECT_BODY: Self = Self("admin.inspect.body");
    pub const ADMIN_PHOTO_UNAVAILABLE_BODY: Self = Self("admin.photo.unavailable.body");
    pub const ADMIN_APPROVE_TITLE: Self = Self("admin.approve.title");
    pub const ADMIN_CHANGES_TITLE: Self = Self("admin.changes.title");
    pub const ADMIN_REJECT_TITLE: Self = Self("admin.reject.title");
    pub const ADMIN_REASON_BODY: Self = Self("admin.reason.body");
    pub const ADMIN_REASON_OPEN_TITLE: Self = Self("admin.reason.open.title");
    pub const ADMIN_REASON_INCOMPLETE_TITLE: Self = Self("admin.reason.incomplete.title");
    pub const ADMIN_REASON_INCOMPLETE_DESC: Self = Self("admin.reason.incomplete.desc");
    pub const ADMIN_REASON_MISMATCH_TITLE: Self = Self("admin.reason.mismatch.title");
    pub const ADMIN_REASON_MISMATCH_DESC: Self = Self("admin.reason.mismatch.desc");
    pub const ADMIN_REASON_PHOTO_TITLE: Self = Self("admin.reason.photo.title");
    pub const ADMIN_REASON_PHOTO_DESC: Self = Self("admin.reason.photo.desc");
    pub const ADMIN_REASON_POLICY_TITLE: Self = Self("admin.reason.policy.title");
    pub const ADMIN_REASON_POLICY_DESC: Self = Self("admin.reason.policy.desc");
    pub const ADMIN_CONFIRM_APPROVE_BODY: Self = Self("admin.confirm.approve.body");
    pub const ADMIN_CONFIRM_CHANGES_BODY: Self = Self("admin.confirm.changes.body");
    pub const ADMIN_CONFIRM_REJECT_BODY: Self = Self("admin.confirm.reject.body");
    pub const ADMIN_CONFIRM_YES_TITLE: Self = Self("admin.confirm.yes.title");
    pub const ADMIN_CONFIRM_NO_TITLE: Self = Self("admin.confirm.no.title");
    pub const ADMIN_DONE_BODY: Self = Self("admin.done.body");

    /// Complete key set required from every locale.
    pub const ALL: &'static [Self] = &[
        Self::LANGUAGE_SELECT_BODY,
        Self::LANGUAGE_OPTION_EN,
        Self::LANGUAGE_OPTION_HI,
        Self::LANGUAGE_OPTION_MR,
        Self::LANGUAGE_CONFIRM_BODY,
        Self::LANGUAGE_CONFIRM_YES,
        Self::LANGUAGE_CONFIRM_CHANGE,
        Self::LANGUAGE_SAVED_BODY,
        Self::LANGUAGE_CHANGE_BODY,
        Self::MAIN_BODY,
        Self::MAIN_FIND,
        Self::MAIN_OFFER,
        Self::MAIN_MORE,
        Self::MORE_BODY,
        Self::MORE_OPEN,
        Self::MORE_AVAILABILITY_TITLE,
        Self::MORE_AVAILABILITY_DESC,
        Self::MORE_REQUESTS_TITLE,
        Self::MORE_REQUESTS_DESC,
        Self::MORE_CONTACTS_TITLE,
        Self::MORE_CONTACTS_DESC,
        Self::MORE_ACCOUNT_TITLE,
        Self::MORE_ACCOUNT_DESC,
        Self::MORE_HELP_TITLE,
        Self::MORE_HELP_DESC,
        Self::MORE_LANGUAGE_TITLE,
        Self::MORE_LANGUAGE_DESC,
        Self::MORE_ADMIN_TITLE,
        Self::MORE_ADMIN_DESC,
        Self::NAV_BACK,
        Self::NAV_CANCEL,
        Self::NAV_MAIN,
        Self::NAV_BACK_AT_ROOT_BODY,
        Self::CANCEL_CONFIRM_BODY,
        Self::CANCEL_YES,
        Self::CANCEL_NO,
        Self::CANCEL_DONE_BODY,
        Self::CANCEL_NONE_BODY,
        Self::HELP_MENU_BODY,
        Self::HELP_MENU_OPEN,
        Self::HELP_ABOUT_TITLE,
        Self::HELP_ABOUT_DESC,
        Self::HELP_ABOUT_BODY,
        Self::HELP_REPORT_TITLE,
        Self::HELP_REPORT_DESC,
        Self::HELP_EMERGENCY_TITLE,
        Self::HELP_EMERGENCY_DESC,
        Self::HELP_EMERGENCY_BODY,
        Self::INPUT_UNKNOWN_BODY,
        Self::SELECTION_STALE_BODY,
        Self::SESSION_EXPIRED_BODY,
        Self::FUTURE_GENERIC_BODY,
        Self::FUTURE_OFFER_BODY,
        Self::AVAILABILITY_ROLE_DENIED_BODY,
        Self::AVAILABILITY_APPROVAL_REQUIRED_BODY,
        Self::AVAILABILITY_SUSPENDED_BODY,
        Self::AVAILABILITY_TIME_ZONE_BODY,
        Self::AVAILABILITY_THROTTLED_BODY,
        Self::AVAILABILITY_UNAVAILABLE_BODY,
        Self::AVAILABILITY_EXPIRED_STATUS_BODY,
        Self::AVAILABILITY_AVAILABLE_BODY,
        Self::AVAILABILITY_STOPPED_BODY,
        Self::AVAILABILITY_CAPACITY_PAUSED_BODY,
        Self::AVAILABILITY_SUCCESSOR_NONE,
        Self::AVAILABILITY_SUCCESSOR_SCHEDULED,
        Self::AVAILABILITY_EXPIRY_LABEL,
        Self::AVAILABILITY_CONTACTS_LABEL,
        Self::AVAILABILITY_SET_TITLE,
        Self::AVAILABILITY_RENEW_TITLE,
        Self::AVAILABILITY_STOP_TITLE,
        Self::AVAILABILITY_RESUME_TITLE,
        Self::AVAILABILITY_VIEW_STATUS_TITLE,
        Self::AVAILABILITY_START_DURATION_BODY,
        Self::AVAILABILITY_RENEW_DURATION_BODY,
        Self::AVAILABILITY_DURATION_OPEN_TITLE,
        Self::AVAILABILITY_DURATION_SECTION_TITLE,
        Self::AVAILABILITY_DURATION_ONE_HOUR_TITLE,
        Self::AVAILABILITY_DURATION_FOUR_HOURS_TITLE,
        Self::AVAILABILITY_DURATION_END_OF_DAY_TITLE,
        Self::AVAILABILITY_STOP_CONFIRM_BODY,
        Self::AVAILABILITY_STOP_CONFIRM_TITLE,
        Self::AVAILABILITY_STOP_CANCEL_TITLE,
        Self::AVAILABILITY_CHANGED_STARTED_BODY,
        Self::AVAILABILITY_CHANGED_RESUMED_BODY,
        Self::AVAILABILITY_CHANGED_STOPPED_BODY,
        Self::AVAILABILITY_CHANGED_RENEWED_BODY,
        Self::AVAILABILITY_CHANGED_CHECK_BODY,
        Self::AVAILABILITY_REMINDER_BODY,
        Self::AVAILABILITY_EXPIRED_BODY,
        Self::AVAILABILITY_LIMIT_BODY,
        Self::DISCOVERY_CATEGORY_BODY,
        Self::DISCOVERY_CATEGORY_PLUMBER,
        Self::DISCOVERY_CATEGORY_ELECTRICIAN,
        Self::DISCOVERY_LOCATION_BODY,
        Self::DISCOVERY_TIME_BODY,
        Self::DISCOVERY_TIME_NOW,
        Self::DISCOVERY_TIME_TODAY,
        Self::DISCOVERY_TIME_FLEXIBLE,
        Self::DISCOVERY_ISSUE_PLUMBER_BODY,
        Self::DISCOVERY_ISSUE_ELECTRICIAN_BODY,
        Self::DISCOVERY_ISSUE_OPEN,
        Self::DISCOVERY_ISSUE_LEAK,
        Self::DISCOVERY_ISSUE_BLOCKAGE,
        Self::DISCOVERY_ISSUE_INSTALLATION,
        Self::DISCOVERY_ISSUE_OUTAGE,
        Self::DISCOVERY_ISSUE_WIRING,
        Self::DISCOVERY_ISSUE_OTHER,
        Self::DISCOVERY_SEARCH_COMPLETE_BODY,
        Self::DISCOVERY_VIEW_RESULTS,
        Self::DISCOVERY_RESULTS_BODY,
        Self::DISCOVERY_RESULTS_OPEN,
        Self::DISCOVERY_RESULTS_SECTION,
        Self::DISCOVERY_NO_RESULTS_BODY,
        Self::DISCOVERY_EXPAND_TITLE,
        Self::DISCOVERY_EXPAND_DESC,
        Self::DISCOVERY_SHOW_MORE_TITLE,
        Self::DISCOVERY_SHOW_MORE_DESC,
        Self::DISCOVERY_DISTANCE_UNDER_ONE,
        Self::DISCOVERY_DISTANCE_UNDER_FIVE,
        Self::DISCOVERY_DISTANCE_UNDER_TEN,
        Self::DISCOVERY_DISTANCE_FARTHER,
        Self::DISCOVERY_AVAILABLE_RECENT,
        Self::DISCOVERY_AVAILABLE_NOW,
        Self::DISCOVERY_IDENTITY_CHECKED,
        Self::DISCOVERY_DIRECT_LABEL,
        Self::DISCOVERY_APPROVAL_LABEL,
        Self::DISCOVERY_CONFIRM_DIRECT_BODY,
        Self::DISCOVERY_CONFIRM_APPROVAL_BODY,
        Self::DISCOVERY_CONFIRM_YES,
        Self::DISCOVERY_CONFIRM_CANCEL,
        Self::DISCOVERY_DIRECT_PROCESSING_BODY,
        Self::DISCOVERY_REQUEST_SENT_BODY,
        Self::DISCOVERY_WAITING_BODY,
        Self::DISCOVERY_REQUEST_CANCEL_TITLE,
        Self::DISCOVERY_REQUEST_CANCELLED_BODY,
        Self::RECENT_CONTACTS_BODY,
        Self::RECENT_CONTACTS_EMPTY_BODY,
        Self::RECENT_CONTACTS_OPEN,
        Self::RECENT_CONTACT_PROCESSING_BODY,
        Self::REQUESTS_LIST_BODY,
        Self::REQUESTS_EMPTY_BODY,
        Self::REQUESTS_OPEN_TITLE,
        Self::REQUESTS_INSPECT_BODY,
        Self::REQUESTS_STALE_BODY,
        Self::REQUESTS_ACCEPT_TITLE,
        Self::REQUESTS_DECLINE_TITLE,
        Self::REQUESTS_ACCEPT_CONFIRM_BODY,
        Self::REQUESTS_DECLINE_CONFIRM_BODY,
        Self::REQUESTS_CONFIRM_TITLE,
        Self::REQUESTS_CANCEL_TITLE,
        Self::REQUESTS_ACCEPTED_BODY,
        Self::REQUESTS_DECLINED_BODY,
        Self::CONNECTION_CONTACT_BODY,
        Self::CONNECTION_CALL_LABEL,
        Self::CONNECTION_WHATSAPP_LABEL,
        Self::CONNECTION_DIRECT_NOTIFY_BODY,
        Self::CONNECTION_REQUEST_NOTIFY_BODY,
        Self::CONNECTION_CUSTOMER_LIMIT_BODY,
        Self::CONNECTION_CAPACITY_BODY,
        Self::FUTURE_ACCOUNT_BODY,
        Self::BILLING_FREE_BODY,
        Self::BILLING_PAYMENT_REQUIRED_BODY,
        Self::BILLING_PENDING_BODY,
        Self::BILLING_ACTIVE_BODY,
        Self::BILLING_GRACE_BODY,
        Self::BILLING_EXPIRED_BODY,
        Self::BILLING_WAIVED_BODY,
        Self::TRUST_LIST_BODY,
        Self::TRUST_EMPTY_BODY,
        Self::TRUST_LIST_TITLE,
        Self::TRUST_CUSTOMER_TITLE,
        Self::TRUST_ACTIONS_BODY,
        Self::TRUST_REVIEW_TITLE,
        Self::TRUST_REPORT_TITLE,
        Self::TRUST_BLOCK_TITLE,
        Self::TRUST_NO_BLOCK_TITLE,
        Self::TRUST_CONFIRM_TITLE,
        Self::TRUST_SKIP_TITLE,
        Self::TRUST_RATING_TITLE,
        Self::TRUST_REVIEW_CONNECTION_BODY,
        Self::TRUST_REVIEW_RESPONSIVENESS_BODY,
        Self::TRUST_REVIEW_COMPLETION_BODY,
        Self::TRUST_REVIEW_FEEDBACK_BODY,
        Self::TRUST_REVIEW_SUBMITTED_BODY,
        Self::TRUST_REPORT_CATEGORY_BODY,
        Self::TRUST_REPORT_BLOCK_BODY,
        Self::TRUST_REPORT_DESCRIPTION_BODY,
        Self::TRUST_REPORT_SUBMITTED_BODY,
        Self::TRUST_BLOCK_CONFIRM_BODY,
        Self::TRUST_BLOCKED_BODY,
        Self::TRUST_STALE_BODY,
        Self::TRUST_CATEGORY_SPAM,
        Self::TRUST_CATEGORY_HARASSMENT,
        Self::TRUST_CATEGORY_FRAUD,
        Self::TRUST_CATEGORY_UNSAFE,
        Self::TRUST_CATEGORY_IDENTITY,
        Self::TRUST_CATEGORY_NO_SHOW,
        Self::TRUST_CATEGORY_OTHER,
        Self::SAFETY_ADMIN_QUEUE_TITLE,
        Self::SAFETY_ADMIN_QUEUE_BODY,
        Self::SAFETY_ADMIN_EMPTY_BODY,
        Self::SAFETY_ADMIN_INSPECT_BODY,
        Self::SAFETY_ADMIN_ACTION_TITLE,
        Self::SAFETY_ADMIN_NO_ACTION,
        Self::SAFETY_ADMIN_WARNING,
        Self::SAFETY_ADMIN_SUSPEND,
        Self::SAFETY_ADMIN_REMOVE,
        Self::SAFETY_ADMIN_CONFIRM_BODY,
        Self::SAFETY_ADMIN_RESOLVED_BODY,
        Self::SAFETY_RESOLUTION_NOTICE_BODY,
        Self::SAFETY_REPORTER_RESOLUTION_BODY,
        Self::FUTURE_REPORT_BODY,
        Self::PRO_NAME_BODY,
        Self::PRO_NAME_INVALID_BODY,
        Self::PRO_NAME_CONFIRM_BODY,
        Self::PRO_NAME_USE_TITLE,
        Self::PRO_NAME_CHANGE_TITLE,
        Self::PRO_CATEGORIES_BODY,
        Self::PRO_CATEGORY_PLUMBER_TITLE,
        Self::PRO_CATEGORY_ELECTRICIAN_TITLE,
        Self::PRO_SELECTION_DONE_TITLE,
        Self::PRO_SELECTION_REQUIRED_BODY,
        Self::PRO_SKILLS_PLUMBER_BODY,
        Self::PRO_SKILLS_ELECTRICIAN_BODY,
        Self::PRO_SKILL_LEAK_TITLE,
        Self::PRO_SKILL_FIXTURE_TITLE,
        Self::PRO_SKILL_DRAIN_TITLE,
        Self::PRO_SKILL_WIRING_TITLE,
        Self::PRO_SKILL_SWITCH_TITLE,
        Self::PRO_SKILL_FAN_TITLE,
        Self::PRO_AREA_BODY,
        Self::PRO_AREA_TRAVEL_TITLE,
        Self::PRO_AREA_VISITS_TITLE,
        Self::PRO_AREA_BOTH_TITLE,
        Self::PRO_LOCATION_BODY,
        Self::PRO_RADIUS_BODY,
        Self::PRO_RADIUS_OPEN_TITLE,
        Self::PRO_RADIUS_2_TITLE,
        Self::PRO_RADIUS_5_TITLE,
        Self::PRO_RADIUS_10_TITLE,
        Self::PRO_RADIUS_25_TITLE,
        Self::PRO_LANGUAGES_BODY,
        Self::PRO_LANGUAGES_OPEN_TITLE,
        Self::PRO_CONTACT_PLUMBER_BODY,
        Self::PRO_CONTACT_ELECTRICIAN_BODY,
        Self::PRO_CONTACT_DIRECT_TITLE,
        Self::PRO_CONTACT_APPROVAL_TITLE,
        Self::PRO_LIMIT_BODY,
        Self::PRO_LIMIT_OPEN_TITLE,
        Self::PRO_LIMIT_1_TITLE,
        Self::PRO_LIMIT_3_TITLE,
        Self::PRO_LIMIT_5_TITLE,
        Self::PRO_LIMIT_10_TITLE,
        Self::PRO_PHOTO_BODY,
        Self::PRO_PHOTO_SKIP_TITLE,
        Self::PRO_PHOTO_REMOVE_TITLE,
        Self::PRO_DISCLOSURE_BODY,
        Self::PRO_CONTINUE_TITLE,
        Self::PRO_CONSENT_BODY,
        Self::PRO_CONSENT_ACCEPT_TITLE,
        Self::PRO_SUMMARY_BODY,
        Self::PRO_SUMMARY_DISPLAY_LABEL,
        Self::PRO_SUMMARY_CATEGORIES_LABEL,
        Self::PRO_SUMMARY_SKILLS_LABEL,
        Self::PRO_SUMMARY_AREA_LABEL,
        Self::PRO_SUMMARY_RADIUS_LABEL,
        Self::PRO_SUMMARY_LANGUAGES_LABEL,
        Self::PRO_SUMMARY_CONTACT_LABEL,
        Self::PRO_SUMMARY_LIMIT_LABEL,
        Self::PRO_SUMMARY_PHOTO_LABEL,
        Self::PRO_SUMMARY_IDENTITY_LABEL,
        Self::PRO_SUMMARY_SUBMIT_TITLE,
        Self::PRO_SUMMARY_EDIT_TITLE,
        Self::PRO_VALUE_NONE,
        Self::PRO_VALUE_PHOTO_PRESENT,
        Self::PRO_VALUE_PHOTO_NONE,
        Self::PRO_VALUE_IDENTITY_CHECKED,
        Self::PRO_VALUE_IDENTITY_NOT_CHECKED,
        Self::PRO_VALUE_CONTACT_DIRECT,
        Self::PRO_VALUE_CONTACT_APPROVAL,
        Self::PRO_VALUE_AREA_TRAVEL,
        Self::PRO_VALUE_AREA_VISITS,
        Self::PRO_VALUE_AREA_BOTH,
        Self::PRO_SUBMITTED_BODY,
        Self::PRO_STATUS_DRAFT_BODY,
        Self::PRO_STATUS_PENDING_BODY,
        Self::PRO_STATUS_CHANGES_BODY,
        Self::PRO_STATUS_APPROVED_BODY,
        Self::PRO_STATUS_REJECTED_BODY,
        Self::PRO_STATUS_HIDDEN_BODY,
        Self::PRO_STATUS_RESUME_TITLE,
        Self::PRO_STATUS_EDIT_TITLE,
        Self::PRO_EDIT_BODY,
        Self::PRO_EDIT_OPEN_TITLE,
        Self::PRO_FIELD_DISPLAY_NAME_TITLE,
        Self::PRO_FIELD_SERVICES_TITLE,
        Self::PRO_FIELD_AREA_TITLE,
        Self::PRO_FIELD_LANGUAGES_TITLE,
        Self::PRO_FIELD_CONTACT_TITLE,
        Self::PRO_FIELD_PHOTO_TITLE,
        Self::ADMIN_DENIED_BODY,
        Self::ADMIN_QUEUE_BODY,
        Self::ADMIN_QUEUE_EMPTY_BODY,
        Self::ADMIN_QUEUE_OPEN_TITLE,
        Self::ADMIN_QUEUE_SECTION_TITLE,
        Self::ADMIN_QUEUE_NEXT_TITLE,
        Self::ADMIN_QUEUE_PREVIOUS_TITLE,
        Self::ADMIN_INSPECT_BODY,
        Self::ADMIN_PHOTO_UNAVAILABLE_BODY,
        Self::ADMIN_APPROVE_TITLE,
        Self::ADMIN_CHANGES_TITLE,
        Self::ADMIN_REJECT_TITLE,
        Self::ADMIN_REASON_BODY,
        Self::ADMIN_REASON_OPEN_TITLE,
        Self::ADMIN_REASON_INCOMPLETE_TITLE,
        Self::ADMIN_REASON_INCOMPLETE_DESC,
        Self::ADMIN_REASON_MISMATCH_TITLE,
        Self::ADMIN_REASON_MISMATCH_DESC,
        Self::ADMIN_REASON_PHOTO_TITLE,
        Self::ADMIN_REASON_PHOTO_DESC,
        Self::ADMIN_REASON_POLICY_TITLE,
        Self::ADMIN_REASON_POLICY_DESC,
        Self::ADMIN_CONFIRM_APPROVE_BODY,
        Self::ADMIN_CONFIRM_CHANGES_BODY,
        Self::ADMIN_CONFIRM_REJECT_BODY,
        Self::ADMIN_CONFIRM_YES_TITLE,
        Self::ADMIN_CONFIRM_NO_TITLE,
        Self::ADMIN_DONE_BODY,
    ];

    /// Returns the catalog key text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Catalog construction or completeness failure.
#[derive(Debug, Error)]
pub enum LocalizationError {
    #[error("localization catalog is not valid JSON")]
    InvalidJson,
    #[error("localization catalog has missing, extra, empty, or oversized entries")]
    InvalidCatalog,
}

/// Immutable validated localization catalogs.
pub struct Localizer {
    catalogs: BTreeMap<Locale, BTreeMap<String, String>>,
}

impl Localizer {
    /// Parses and validates every embedded locale.
    pub fn load() -> Result<Self, LocalizationError> {
        let mut catalogs = BTreeMap::new();
        for (locale, source) in [
            (Locale::EnIn, EN_IN),
            (Locale::HiIn, HI_IN),
            (Locale::MrIn, MR_IN),
        ] {
            let catalog: BTreeMap<String, String> =
                serde_json::from_str(source).map_err(|_| LocalizationError::InvalidJson)?;
            validate_catalog(&catalog)?;
            catalogs.insert(locale, catalog);
        }
        Ok(Self { catalogs })
    }

    /// Returns translated text with an English fallback that should never be needed
    /// after successful catalog validation.
    #[must_use]
    pub fn text(&self, locale: Locale, key: MessageKey) -> &str {
        self.catalogs
            .get(&locale)
            .and_then(|catalog| catalog.get(key.as_str()))
            .or_else(|| {
                self.catalogs
                    .get(&Locale::EnIn)
                    .and_then(|catalog| catalog.get(key.as_str()))
            })
            .map_or("", String::as_str)
    }
}

impl fmt::Debug for Localizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Localizer")
            .field("locales", &self.catalogs.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn validate_catalog(catalog: &BTreeMap<String, String>) -> Result<(), LocalizationError> {
    let expected: BTreeSet<_> = MessageKey::ALL.iter().map(|key| key.as_str()).collect();
    let actual: BTreeSet<_> = catalog.keys().map(String::as_str).collect();
    if expected != actual {
        return Err(LocalizationError::InvalidCatalog);
    }
    for &key in MessageKey::ALL {
        let value = catalog
            .get(key.as_str())
            .ok_or(LocalizationError::InvalidCatalog)?;
        let limit = message_limit(key.as_str());
        let count = value.encode_utf16().count();
        if value.trim().is_empty() || count > limit || value.chars().any(|ch| ch == '\0') {
            return Err(LocalizationError::InvalidCatalog);
        }
    }
    Ok(())
}

fn message_limit(key: &str) -> usize {
    if key == "professional.consent.body" {
        1_024
    } else if matches!(
        key,
        "language.option.en.title"
            | "language.option.hi.title"
            | "language.option.mr.title"
            | "language.confirm.yes.title"
            | "language.confirm.change.title"
            | "main.find.title"
            | "main.offer.title"
            | "main.more.title"
            | "more.open.title"
            | "nav.back.title"
            | "nav.cancel.title"
            | "nav.main.title"
            | "cancel.yes.title"
            | "cancel.no.title"
            | "help.menu.open.title"
    ) {
        20
    } else if key.ends_with(".title") {
        24
    } else if key.ends_with(".desc") {
        72
    } else {
        4_096
    }
}

#[cfg(test)]
mod tests {
    use super::{Locale, Localizer, MessageKey};

    #[test]
    fn every_catalog_is_complete_and_within_whatsapp_limits()
    -> Result<(), Box<dyn std::error::Error>> {
        let localizer = Localizer::load()?;
        for locale in Locale::ALL {
            for &key in MessageKey::ALL {
                assert!(!localizer.text(locale, key).is_empty());
            }
            assert!(
                localizer
                    .text(locale, MessageKey::PRO_CONSENT_BODY)
                    .encode_utf16()
                    .count()
                    <= 1_024
            );
        }
        Ok(())
    }

    #[test]
    fn locale_aliases_are_stable() {
        assert_eq!(Locale::parse("hi"), Some(Locale::HiIn));
        assert_eq!(Locale::EnIn.meta_template_code(), "en_IN");
        assert_eq!(Locale::MrIn.meta_template_code(), "mr");
        assert_eq!(Locale::parse("unknown"), None);
    }
}
