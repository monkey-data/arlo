from datetime import datetime
import uuid
from collections import defaultdict
from sqlalchemy.orm.session import Session
from flask import request, jsonify, Request
from werkzeug.exceptions import BadRequest, NotFound, Conflict

from . import api
from ..database import db_session
from ..models import *  # pylint: disable=wildcard-import
from ..auth import restrict_access, UserType
from .rounds import is_round_complete, end_round
from ..util.process_file import (
    process_file,
    serialize_file,
    serialize_file_processing,
    UserError,
)
from ..util.csv_download import csv_response
from ..util.csv_parse import decode_csv_file, parse_csv, CSVValueType, CSVColumnType

BATCH_NAME = "Batch Name"


def process_batch_results_file(
    session: Session,
    jurisdiction: Jurisdiction,
    contest: Contest,
    round: Round,
    file: File,
):
    def process():
        columns = [CSVColumnType(BATCH_NAME, CSVValueType.TEXT, unique=True)] + [
            CSVColumnType(choice.name, CSVValueType.NUMBER)
            for choice in contest.choices
        ]

        batch_results_csv = list(
            parse_csv(jurisdiction.batch_results_file.contents, columns)
        )

        # Validate that the batch names match the ballot manifest
        jurisdiction_batch_names = {batch.name for batch in jurisdiction.batches}
        results_batch_names = {row[BATCH_NAME] for row in batch_results_csv}
        extra_batch_names = sorted(results_batch_names - jurisdiction_batch_names)
        missing_batch_names = sorted(jurisdiction_batch_names - results_batch_names)
        if extra_batch_names or missing_batch_names:
            raise UserError(
                "Batch names must match the ballot manifest file."
                + (
                    "\nFound extra batch names: " + ", ".join(extra_batch_names)
                    if extra_batch_names
                    else ""
                )
                + (
                    "\nFound missing batch names: " + ", ".join(missing_batch_names)
                    if missing_batch_names
                    else ""
                )
            )

        # Validate that the sum results for each batch don't exceed the allowed votes
        num_ballots_by_batch = {
            batch.name: batch.num_ballots for batch in jurisdiction.batches
        }
        for row in batch_results_csv:
            allowed_tallies = (
                num_ballots_by_batch[row[BATCH_NAME]] * contest.votes_allowed
            )
            total_tallies = sum(row[choice.name] for choice in contest.choices)
            if total_tallies > allowed_tallies:
                raise UserError(
                    f'The total votes for batch "{row[BATCH_NAME]}" ({total_tallies} votes)'
                    + f" cannot exceed {allowed_tallies} - the number of ballots from the manifest"
                    + f" ({num_ballots_by_batch[row[BATCH_NAME]]} ballots) multipled by the number"
                    + f" of votes allowed for the contest ({contest.votes_allowed} votes per ballot)."
                )

        # Sum the results and save them as JurisdictionResults
        # audit_math.macro module, so we can easily load it up and pass it in
        sum_results = defaultdict(0)
        for row in batch_results_csv:
            for choice in contest.choices:
                sum_results[choice.id] += row[choice.name]

        jurisdiction_results = [
            JurisdictionResult(
                round_id=round.id,
                contest_id=contest.id,
                jurisdiction_id=jurisdiction.id,
                contest_choice_id=choice_id,
                result=result,
            )
            for choice_id, result in sum_results.items()
        ]
        db_session.add_all(jurisdiction_results)

        if is_round_complete(jurisdiction.election, round):
            end_round(jurisdiction.election, round)

    process_file(session, file, process)


# Raises if invalid
def validate_batch_results_upload(
    request: Request, election: Election, jurisdiction: Jurisdiction, contest: Contest
):
    if election.audit_type != AuditType.BALLOT_POLLING:
        raise Conflict("Can only upload batch results file for ballot polling audits.")

    if not any(c.id == contest.id for c in jurisdiction.contests):
        raise Conflict("Jurisdiction is not in contest universe")

    if "batchResults" not in request.files:
        raise BadRequest("Missing required file parameter 'batchResults'")


def clear_batch_results_file(
    jurisdiction: Jurisdiction, round: Round, contest: Contest
):
    if jurisdiction.batch_results_file:
        db_session.delete(jurisdiction.batch_results_file)
        JurisdictionResult.query.filter_by(
            round_id=round.id, contest_id=contest.id, jurisdiction_id=jurisdiction.id,
        ).delete()


@api.route(
    "/election/<election_id>/jurisdiction/<jurisdiction_id>/round/<round_id>/contest/<contest_id>/batch-results",
    methods=["PUT"],
)
@restrict_access([UserType.JURISDICTION_ADMIN])
def upload_batch_results(
    election: Election, jurisdiction: Jurisdiction, round: Round, contest_id: str,
):
    contest = Contest.query.get(contest_id)
    validate_batch_results_upload(request, election, jurisdiction, contest)

    clear_batch_results_file(jurisdiction, round, contest)

    # We save the batch results file, and bgcompute finds it and processes it in
    # the background.
    batch_results = request.files["batchResults"]
    db_session.add(
        JurisdictionBatchResults(
            jurisdiction_id=jurisdiction.id,
            round_id=round.id,
            contest_id=contest.id,
            file=File(
                id=str(uuid.uuid4()),
                name=batch_results.filename,
                contents=decode_csv_file(batch_results.read()),
                uploaded_at=datetime.utcnow(),
            ),
        )
    )
    db_session.commit()
    return jsonify(status="ok")


@api.route(
    "/election/<election_id>/jurisdiction/<jurisdiction_id>/round/<round_id>/contest/<contest_id>/batch-results",
    methods=["GET"],
)
@restrict_access([UserType.JURISDICTION_ADMIN])
def get_batch_results(
    election: Election, jurisdiction: Jurisdiction, round: Round, contest_id: str,
):
    return jsonify(
        file=serialize_file(jurisdiction.batch_results_file),
        processing=serialize_file_processing(jurisdiction.batch_tallies_file),
    )


@api.route(
    "/election/<election_id>/jurisdiction/<jurisdiction_id>/batch-tallies/csv",
    methods=["GET"],
)
@restrict_access([UserType.AUDIT_ADMIN])
def download_batch_tallies_file(
    election: Election, jurisdiction: Jurisdiction,  # pylint: disable=unused-argument
):
    if not jurisdiction.batch_tallies_file:
        return NotFound()

    return csv_response(
        jurisdiction.batch_tallies_file.contents, jurisdiction.batch_tallies_file.name
    )


@api.route(
    "/election/<election_id>/jurisdiction/<jurisdiction_id>/batch-tallies",
    methods=["DELETE"],
)
@restrict_access([UserType.JURISDICTION_ADMIN])
def clear_batch_tallies(
    election: Election, jurisdiction: Jurisdiction,  # pylint: disable=unused-argument
):
    clear_batch_tallies_file(jurisdiction)
    db_session.commit()
    return jsonify(status="ok")
