"""Netlify Function: wraps the Flask app as a serverless Lambda handler."""
import os
import sys

# Point sys.path at the project root (two levels up from netlify/functions/)
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _root)

# Set cwd so Flask can resolve templates/, static/, and data/ relative paths
os.chdir(_root)

from app import app  # noqa: E402  (import after path/cwd setup)
import awsgi         # noqa: E402


def handler(event, context):
    # base64_content_types ensures PDF responses are binary-safe
    return awsgi.response(
        app, event, context,
        base64_content_types={"application/pdf"},
    )
