"""The agents whose actions Warrant authorizes.

providers/ (W4) holds one interface over the model APIs. loop.py (W10) holds
the provider and tool loop the roles share. triage.py and support.py (W10) are
the two roles, each supplying its prompt, its agent client, and its tools, and
each proposing actions that the service allows or denies. run_many.py runs
several tasks at once, one token and one run directory per task.
"""
