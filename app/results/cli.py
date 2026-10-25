import click
from flask.cli import with_appcontext

from app.elections.models import Election
from app.extensions import db
from app.models import User
from app.results.publication import ResultsError
from app.results.tally import TallyError, count_and_publish


@click.command("publish-results")
@click.argument("election_id", type=int)
@click.option("--admin", "admin_email", required=True, help="Email of the administrator publishing.")
@click.option("--share", "share_files", multiple=True, required=True,
              type=click.Path(exists=True, dir_okay=False), help="A trustee key share file (give 3).")
@with_appcontext
def publish_results_command(election_id, admin_email, share_files):
    """Decrypt and count an election's ballots, then publish signed results."""
    election = db.session.get(Election, election_id)
    if election is None:
        raise click.ClickException(f"Election {election_id} not found.")
    admin = db.session.execute(db.select(User).filter_by(email=admin_email)).scalar_one_or_none()
    if admin is None:
        raise click.ClickException(f"No user with email {admin_email}.")

    shares = []
    for path in share_files:
        with open(path) as share_file:
            shares.append(share_file.read())

    try:
        publication = count_and_publish(election, admin, shares)
    except (TallyError, ResultsError) as error:
        raise click.ClickException(str(error))
    click.echo(f"Published signed results for election {election_id} "
               f"(document hash {publication.document_hash}).")
