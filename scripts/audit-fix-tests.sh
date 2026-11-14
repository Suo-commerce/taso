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
one a_record_refused_before_the_log_leaves_nothing_pending $W
one a_leader_hands_over_after_its_own_group $W
one a_slow_store_read_does_not_hold_other_requests $W
one a_slow_read_of_an_accept_does_not_hold_other_requests $W
# The agent's side: the session, the verifier, the ledger
one a_child_name_no_fork_could_have_is_refused_before_the_hooks $W
one a_subject_longer_than_a_resource_may_have_is_refused $W
one the_last_turn_number_is_refused_and_later_turns_still_seal $W
one a_nominate_refusal_quotes_only_the_start_of_a_name $W
one a_kill_that_did_not_take_is_asked_for_again $W
one a_failed_append_consumes_no_op_id $W
one an_effect_request_over_the_limit_is_refused_and_not_recorded $W
one of_what_an_agent_prints_the_warden_keeps_the_end $W
one transcript_between_two_seals_is_bounded_and_a_seal_makes_room $W
one a_full_outbox_refuses_a_new_effect_until_an_outcome_is_reported $W
one a_promotion_that_would_overfill_the_outbox_is_refused_before_it_is_recorded $W
# Forks
one a_parent_with_a_live_fork_on_this_node_is_not_purged $W
one a_requested_child_outlives_its_parents_entry $W
one an_agents_declared_authority_is_not_an_adoption $W
one a_fork_asked_again_from_a_newer_seal_replaces_the_interrupted_clone $W
one a_fork_slot_is_taken_by_a_born_child_not_by_a_directory $W
# Verification attempts
one a_restore_walk_cut_short_by_this_nodes_clock_is_interrupted $W
one a_failed_look_for_candidates_is_tried_again_after_a_wait $W
one the_pending_list_fails_when_the_coordinator_cannot_say_who_holds_a_vessel $W
# Purges
one a_refused_record_retried_does_not_grow_the_log $W
one a_purge_finished_on_another_node_deletes_that_nodes_dataset $W
# Genesis
one a_layer_record_never_accepted_gives_way_to_a_rebuild $W
one no_new_namespace_is_made_by_clone_or_clone3 $W
one nothing_of_the_host_is_bound_in_but_the_vessels_own $W
one a_vessel_env_that_steers_the_loader_is_refused $W
one an_env_that_steers_the_loader_is_refused_when_read $W
one each_seal_carries_the_effects_adopted_up_to_it $W
one a_cancel_under_a_stale_epoch_changes_nothing -p taso-core --lib
one a_refusal_is_answered_the_same_until_it_is_forgotten -p taso-core --lib
one a_purge_ends_only_with_no_file_pack_of_the_chronicle_left -p taso-core --lib
one a_purge_deletes_file_packs_only $W
one a_pack_put_after_the_commit_is_deleted_by_the_purge $W
one a_pack_put_after_the_purge_ended_is_deleted_by_the_reclaimer $W
one purged_within_crosses_the_socket $W
one task_and_taken_hashes_are_pinned -p taso-core --lib
one a_resume_never_refuses_a_genesis_from_an_object_that_is_not_its_keys $W
one a_genesis_finished_elsewhere_does_not_leave_the_first_nodes_scratch $W
# The reclaimer
one a_pass_claims_nothing_the_coordinator_says_it_would_refuse $W
# The object store
one a_missing_bucket_is_not_an_absent_object $W
one a_dead_process_temp_file_is_removed_by_a_walk $W
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
# The coordinator's log
one a_never_close_needs_a_never_verdict_of_its_candidate -p taso-core --lib
one a_verdict_over_other_facts_than_the_candidates_is_refused -p taso-core --lib
one a_birth_of_a_retired_chronicle_is_refused -p taso-core --lib
one a_sanction_target_not_yet_ready_is_not_purged -p taso-core --lib
one expiry_by_time_expires_what_the_walk_did -p taso-core --lib
one expiry_does_not_walk_every_chronicle -p taso-core --lib
one accept_reads_reads_what_accept_reads_and_changes_nothing -p taso-core --lib
# Decoding
one a_sequence_reserves_at_most_its_input_before_it_decodes -p taso-core --lib
# taso-ctl
one the_run_directories_are_kept_at_boot -p taso-warden --bin taso-ctl
# The block log
one two_genesis_processes_never_take_down_each_others_views $W
one spool_files_of_a_process_that_is_gone_are_swept $W
one a_view_left_by_a_killed_warden_does_not_block_destroy $W
one a_destroy_cut_short_at_any_step_is_finished_by_a_retry $W
one a_mount_root_written_any_way_names_the_mount_points_the_kernel_lists $W
one a_poisoned_store_does_not_answer_from_a_map_ahead_of_the_file -p taso-blk --lib
one a_poisoned_store_answers_err_to_find_seals_names_and_info -p taso-blk --bin taso-blkd
one a_refused_connection_thread_is_logged_and_the_loop_goes_on -p taso-blk --bin taso-blkd
# The soak's stall (taso-test 2026-11-12, blkd-del)
one ending_a_device_never_waits_for_the_kernel_to_free_it -p taso-blk --bin taso-blkd
one a_device_that_never_stops_refuses_calls_instead_of_holding_them -p taso-blk --bin taso-blkd
one a_deleted_device_the_kernel_keeps_is_counted_until_freed -p taso-blk --bin taso-blkd
# Local Seal retention (S-c, 2026-11-14, seal-fold)
one a_folded_seal_reads_the_same_and_shortens_the_chain -p taso-blk --lib
one depth_max_is_the_longest_chain_and_folds_shorten_it -p taso-blk --lib
one a_fold_is_replayed_from_the_log_and_from_a_checkpoint -p taso-blk --lib
one fold_is_sent_and_its_answer_parsed -p taso-blk --lib
one fold_takes_an_old_seal_out_and_stats_shows_the_shorter_chain -p taso-blk --bin taso-blkd
one a_store_that_does_not_fold_keeps_its_layers $W
one an_old_seal_is_folded_and_the_newest_and_a_forked_one_stay $W
one a_folded_seal_is_in_the_bucket_only_not_missing $W
one old_seals_fold_only_when_nothing_here_needs_them $W
one the_fold_plan_keeps_the_newest_the_unshipped_and_the_pinned $W
one a_fork_from_a_folded_seal_is_refused_and_one_from_the_newest_works $W
one storage_is_the_block_log_and_zfs_is_refused $W

if [ "$bad" = 0 ]; then
    echo "audit-fix-tests: PASS, $n of $n ($OUT)"
else
    echo "audit-fix-tests: $bad of $n FAILED ($OUT)"
    exit 1
fi
