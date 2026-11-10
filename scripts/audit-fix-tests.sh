#!/usr/bin/env bash
# The tests of the fixes for the audit of 2026-11-09, one by one, by name.
#
#   scripts/audit-fix-tests.sh [DIR]
#
# Each test is run alone and its output kept in DIR (default: a new
# directory under /tmp).  One line per test: "ok" or "FAIL", then its
# name.  A name that matches no test is a FAIL: cargo exits 0 for a
# filter that matched nothing.  Exit 0 only if every test ran and passed.
# The whole suite is the release gate's `unit` step; this is for looking
# at each fix by itself.  No root, no devices.
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=${1:-$(mktemp -d /tmp/audit-fix-tests.XXXXXX)}
mkdir -p "$OUT"
bad=0 n=0

one() { # one NAME cargo-test-target...: run the one test NAME
    local name=$1; shift
    n=$((n + 1))
    if cargo test "$@" "$name" > "$OUT/$name.txt" 2>&1 &&
        grep -Eq '^test result: ok\. [1-9][0-9]* passed' "$OUT/$name.txt"; then
        echo "ok    $name"
    else
        echo "FAIL  $name  ($OUT/$name.txt)"
        bad=$((bad + 1))
    fi
}

W="-p taso-warden --lib"
# The coordinator
one a_failed_purge_projection_fails_no_request_grouped_with_it $W
one a_failed_purge_projection_alone_keeps_the_in_memory_log $W
one after_a_restart_one_failed_call_is_enough $W
one a_panicking_worker_closes_its_connection $W
one a_panicking_worker_closes_its_connection_and_frees_its_place $W
one a_cancel_of_an_unowned_chronicle_refuses_nothing_of_its_later_holder $W
one a_cancel_under_a_stale_epoch_refuses_nothing_of_the_pending_submission $W
# The agent's side: the session, the verifier, the ledger
one a_child_name_no_fork_could_have_is_refused_before_the_hooks $W
one a_subject_longer_than_a_resource_may_have_is_refused $W
one the_last_turn_number_is_refused_and_later_turns_still_seal $W
one a_kill_that_did_not_take_is_asked_for_again $W
one a_failed_append_consumes_no_op_id $W
one an_effect_request_over_the_limit_is_refused_and_not_recorded $W
one of_what_an_agent_prints_the_warden_keeps_the_end $W
one transcript_between_two_seals_is_bounded_and_a_seal_makes_room $W
one a_full_outbox_refuses_a_new_effect_until_an_outcome_is_reported $W
one a_promotion_that_would_overfill_the_outbox_is_refused_before_it_is_recorded $W
# The reclaimer
one a_pass_claims_nothing_the_coordinator_says_it_would_refuse $W
# Kubernetes
one a_field_cleared_by_a_later_event_is_cleared_on_the_resource $W
one a_failing_list_is_never_answered_as_unchanged $W
one a_source_error_that_repeats_is_logged_once_in_a_while -p taso-warden --bin taso-wardend
# The Warden's node
one a_vessel_entry_refuses_a_key_it_does_not_know $W
one a_candidate_needs_a_sanction_that_is_not_null $W
one an_empty_ttl_start_file_does_not_stop_the_ttl_for_good $W
one two_threads_keeping_one_ttl_start_both_succeed $W
one a_ttl_start_is_kept_once_and_junk_is_not_guessed $W
one the_queue_settles_after_a_thread_the_os_refused $W
one the_queue_settles_after_a_look_that_panicked $W
one an_agent_nothing_can_stop_is_ended_before_the_run_returns $W
one a_run_that_fails_after_its_agent_started_leaves_no_agent $W
one one_candidates_error_does_not_end_the_pass_for_the_others -p taso-warden --bin taso-policy
# The block log
one a_poisoned_store_does_not_answer_from_a_map_ahead_of_the_file -p taso-blk --lib
one a_poisoned_store_answers_err_to_find_seals_names_and_info -p taso-blk --bin taso-blkd
one a_refused_connection_thread_is_logged_and_the_loop_goes_on -p taso-blk --bin taso-blkd

if [ "$bad" = 0 ]; then
    echo "audit-fix-tests: PASS, $n of $n ($OUT)"
else
    echo "audit-fix-tests: $bad of $n FAILED ($OUT)"
    exit 1
fi
