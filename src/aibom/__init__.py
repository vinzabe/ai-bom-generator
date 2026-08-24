"""aibom — a bill of materials for ML systems, with transitive provenance.

A model is rarely standalone: it is a fine-tune of a merge of a base model trained
on datasets of varying license and origin. "Is this model safe to ship?" is really
"what is its full lineage, and does any ancestor carry a restrictive license or an
undeclared origin?" A flat list of dependencies cannot answer that; a provenance
DAG can.

This tool builds a CycloneDX-ML SBOM from a declared component graph, propagates
licenses transitively, and flags the risks that hide in lineage: a
non-commercial dataset three hops up, an ancestor with no declared source, a
license conflict between a base model and a fine-tuning set.
"""
__version__ = "1.0.0"
