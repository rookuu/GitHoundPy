#!/usr/bin/env python3
"""
GitHound JSON Output Validator

This script validates GitHound JSON output against provided schemas for nodes and edges.
"""

import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import tqdm
from jsonschema import validate, ValidationError


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)


def load_schema(schema_path: Path) -> Dict[str, Any]:
    """Load and return a JSON schema from file."""
    try:
        with open(schema_path, "r") as schema_file:
            return json.load(schema_file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Schema file not found: {schema_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in schema file {schema_path}: {e}")


def load_githound_data(data_path: Path) -> Dict[str, Any]:
    """Load and return GitHound JSON data from file."""
    try:
        with open(data_path, "r") as data_file:
            return json.load(data_file)
    except FileNotFoundError:
        raise FileNotFoundError(f"GitHound data file not found: {data_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in data file {data_path}: {e}")


def validate_single_node(node_data: Tuple[int, Dict[str, Any]], schema: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Validate a single node against the schema. Returns (index, errors)."""
    index, node = node_data
    errors = []
    
    try:
        validate(instance=node, schema=schema)
    except ValidationError as e:
        error_msg = f"Node {index} validation error: {e.message}"
        if hasattr(e, 'absolute_path') and e.absolute_path:
            error_msg += f" (Path: {' -> '.join(map(str, e.absolute_path))})"
        errors.append(error_msg)
    except Exception as e:
        errors.append(f"Node {index} unexpected validation error: {e}")
    
    return index, errors


def validate_single_edge(edge_data: Tuple[int, Dict[str, Any]], schema: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Validate a single edge against the schema. Returns (index, errors)."""
    index, edge = edge_data
    errors = []
    
    try:
        validate(instance=edge, schema=schema)
    except ValidationError as e:
        error_msg = f"Edge {index} validation error: {e.message}"
        if hasattr(e, 'absolute_path') and e.absolute_path:
            error_msg += f" (Path: {' -> '.join(map(str, e.absolute_path))})"
        errors.append(error_msg)
    except Exception as e:
        errors.append(f"Edge {index} unexpected validation error: {e}")
    
    return index, errors


def validate_nodes(nodes: List[Dict[str, Any]], schema: Dict[str, Any], logger: logging.Logger, max_workers: int = None) -> int:
    """Validate all nodes against the node schema using multi-threading. Returns number of errors."""
    if not nodes:
        return 0
        
    errors = 0
    error_lock = Lock()
    logger.info(f"Validating {len(nodes)} nodes with {max_workers or 'auto'} workers...")
    
    # Create enumerated data for processing
    enumerated_nodes = list(enumerate(nodes))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all validation tasks
        future_to_index = {
            executor.submit(validate_single_node, node_data, schema): node_data[0]
            for node_data in enumerated_nodes
        }
        
        # Process completed tasks with progress bar
        with tqdm.tqdm(total=len(nodes), desc="Validating nodes", unit="node") as pbar:
            for future in as_completed(future_to_index):
                index, node_errors = future.result()
                
                if node_errors:
                    with error_lock:
                        errors += len(node_errors)
                        for error_msg in node_errors:
                            logger.error(error_msg)
                else:
                    logger.debug(f"Node {index} validation passed")
                
                pbar.update(1)
    
    return errors


def validate_edges(edges: List[Dict[str, Any]], schema: Dict[str, Any], logger: logging.Logger, max_workers: int = None) -> int:
    """Validate all edges against the edge schema using multi-threading. Returns number of errors."""
    if not edges:
        return 0
        
    errors = 0
    error_lock = Lock()
    logger.info(f"Validating {len(edges)} edges with {max_workers or 'auto'} workers...")
    
    # Create enumerated data for processing
    enumerated_edges = list(enumerate(edges))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all validation tasks
        future_to_index = {
            executor.submit(validate_single_edge, edge_data, schema): edge_data[0]
            for edge_data in enumerated_edges
        }
        
        # Process completed tasks with progress bar
        with tqdm.tqdm(total=len(edges), desc="Validating edges", unit="edge") as pbar:
            for future in as_completed(future_to_index):
                index, edge_errors = future.result()
                
                if edge_errors:
                    with error_lock:
                        errors += len(edge_errors)
                        for error_msg in edge_errors:
                            logger.error(error_msg)
                else:
                    logger.debug(f"Edge {index} validation passed")
                
                pbar.update(1)
    
    return errors


def main():
    """Main function to handle CLI arguments and run validation."""
    parser = argparse.ArgumentParser(
        description="Validate GitHound JSON output against node and edge schemas",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s data.json schema/
  %(prog)s --verbose githound_output.json schema/
  %(prog)s --quiet --no-progress data.json /path/to/schemas/
  %(prog)s --jobs 8 data.json schema/
  %(prog)s -j 4 --verbose data.json schema/
        """
    )
    
    parser.add_argument(
        "githound_output",
        type=Path,
        help="Path to the GitHound JSON output file to validate"
    )
    
    parser.add_argument(
        "schema_dir",
        type=Path,
        help="Path to the directory containing node.json and edge.json schema files"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress bars and reduce output"
    )
    
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bars"
    )
    
    parser.add_argument(
        "--node-schema",
        type=Path,
        help="Custom path to node schema file (default: <schema_dir>/node.json)"
    )
    
    parser.add_argument(
        "--edge-schema",
        type=Path,
        help="Custom path to edge schema file (default: <schema_dir>/edge.json)"
    )
    
    parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=None,
        help="Number of worker threads for parallel validation (default: auto-detect based on CPU cores)"
    )
    
    args = parser.parse_args()
    
    # Set up logging
    logger = setup_logging(verbose=args.verbose and not args.quiet)
    
    # Disable progress bars if quiet or no-progress is specified
    if args.quiet or args.no_progress:
        tqdm.tqdm = lambda x, **kwargs: x
    
    try:
        # Determine schema file paths
        node_schema_path = args.node_schema or (args.schema_dir / "node.json")
        edge_schema_path = args.edge_schema or (args.schema_dir / "edge.json")
        
        logger.info("Loading schemas...")
        node_schema = load_schema(node_schema_path)
        edge_schema = load_schema(edge_schema_path)
        logger.info(f"Loaded node schema from: {node_schema_path}")
        logger.info(f"Loaded edge schema from: {edge_schema_path}")
        
        logger.info("Loading GitHound data...")
        githound_data = load_githound_data(args.githound_output)
        logger.info(f"Loaded data from: {args.githound_output}")
        
        # Extract graph data
        graph = githound_data.get("graph", {})
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        
        if not nodes and not edges:
            logger.warning("No nodes or edges found in the data file")
        
        logger.info(f"Found {len(nodes)} nodes and {len(edges)} edges")
        
        # Set up worker threads
        max_workers = args.jobs
        if max_workers:
            logger.info(f"Using {max_workers} worker threads")
        else:
            logger.info("Using auto-detected number of worker threads")
        
        total_errors = 0
        
        # Validate nodes
        if nodes:
            node_errors = validate_nodes(nodes, node_schema, logger, max_workers)
            total_errors += node_errors
            if node_errors == 0:
                logger.info("✓ All nodes validated successfully")
            else:
                logger.error(f"✗ {node_errors} node validation errors found")
        
        # Validate edges
        if edges:
            edge_errors = validate_edges(edges, edge_schema, logger, max_workers)
            total_errors += edge_errors
            if edge_errors == 0:
                logger.info("✓ All edges validated successfully")
            else:
                logger.error(f"✗ {edge_errors} edge validation errors found")
        
        # Summary
        if total_errors == 0:
            logger.info("🎉 Validation completed successfully - no errors found!")
            sys.exit(0)
        else:
            logger.error(f"❌ Validation failed with {total_errors} total errors")
            sys.exit(1)
            
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Invalid data: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Validation interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            logger.exception("Full traceback:")
        sys.exit(1)


if __name__ == "__main__":
    main()
