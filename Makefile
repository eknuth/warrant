# Warrant. Only the targets that exist today: W1 owns test, lint, and sync.
# Everything here runs from a checkout of this repository.

.PHONY: dsh-profile

# Install the dsh profiles from infra/dsh/ into $DSH_HOME (default ~/.dsh).
# Reproducible and idempotent; see infra/dsh/install-profile.sh.
dsh-profile:
	bash infra/dsh/install-profile.sh
