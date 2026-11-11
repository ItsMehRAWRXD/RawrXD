#!/usr/bin/env python3
"""
Phase A.1: Learning Simulator Visualization
Plots convergence data exported from the simulator

Usage:
    python visualize_simulator.py results.csv
    python visualize_simulator.py results.json
    python visualize_simulator.py results.csv --output plot.png
"""

import json
import csv
import sys
import argparse
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not installed. Install with: pip install matplotlib")

def load_csv(path):
    """Load CSV data from simulator export"""
    data = {
        'iterations': [],
        'agents': {},
        'selection_types': []
    }
    
    with open(path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            data['iterations'].append(int(row['iteration']))
            agent_id = int(row['agent_id'])
            if agent_id not in data['agents']:
                data['agents'][agent_id] = {
                    'name': row['agent_name'],
                    'selected': []
                }
            data['agents'][agent_id]['selected'].append(1 if int(row['agent_id']) == agent_id else 0)
            data['selection_types'].append(row['selection_type'])
    
    return data

def load_json(path):
    """Load JSON data from simulator export"""
    with open(path, 'r') as f:
        return json.load(f)

def plot_convergence(data, output_path=None):
    """Plot assignment convergence over time"""
    if not HAS_MATPLOTLIB:
        print("Cannot plot: matplotlib not available")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Learning Simulator Results', fontsize=14, fontweight='bold')
    
    # Plot 1: Agent selection over time
    ax1 = axes[0, 0]
    snapshots = data.get('snapshots', [])
    
    if snapshots:
        iterations = [s['iteration'] for s in snapshots]
        agent_ids = list(set(s['agent_id'] for s in snapshots))
        
        for agent_id in sorted(agent_ids):
            agent_name = next((s['agent_name'] for s in snapshots if s['agent_id'] == agent_id), f"Agent {agent_id}")
            selections = [1 if s['agent_id'] == agent_id else 0 for s in snapshots]
            
            # Calculate cumulative assignments
            cumulative = []
            total = 0
            for sel in selections:
                total += sel
                cumulative.append(total)
            
            ax1.plot(iterations, cumulative, label=agent_name, linewidth=2)
        
        ax1.set_xlabel('Iteration')
        ax1.set_ylabel('Cumulative Assignments')
        ax1.set_title('Agent Assignment Over Time')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
    
    # Plot 2: Success rate evolution
    ax2 = axes[0, 1]
    if snapshots:
        iterations = [s['iteration'] for s in snapshots]
        success_rates = [s.get('success_rate', 0) for s in snapshots]
        
        ax2.plot(iterations, [r * 100 for r in success_rates], 'g-', linewidth=2)
        ax2.set_xlabel('Iteration')
        ax2.set_ylabel('Success Rate (%)')
        ax2.set_title('Success Rate Evolution')
        ax2.grid(True, alpha=0.3)
        ax2.set_ylim(0, 100)
    
    # Plot 3: Exploration vs Exploitation
    ax3 = axes[1, 0]
    if snapshots:
        iterations = [s['iteration'] for s in snapshots]
        exploration = [1 if s.get('selection_type') == 'exploration' else 0 for s in snapshots]
        
        # Calculate rolling exploration rate
        window = min(100, len(exploration) // 10)
        if window > 0:
            rolling = []
            for i in range(len(exploration)):
                start = max(0, i - window)
                rate = sum(exploration[start:i+1]) / (i - start + 1) * 100
                rolling.append(rate)
            
            ax3.plot(iterations, rolling, 'b-', linewidth=2)
            ax3.axhline(y=10, color='r', linestyle='--', label='Target (10%)')
            ax3.set_xlabel('Iteration')
            ax3.set_ylabel('Exploration Rate (%)')
            ax3.set_title('Exploration Rate Over Time')
            ax3.legend()
            ax3.grid(True, alpha=0.3)
    
    # Plot 4: Worker performance comparison
    ax4 = axes[1, 1]
    workers = data.get('workers', [])
    if workers:
        names = [w['name'] for w in workers]
        expected = [w['expected_success'] * 100 for w in workers]
        actual = [w.get('actual_success_rate', 0) * 100 for w in workers]
        
        x = range(len(names))
        width = 0.35
        
        ax4.bar([i - width/2 for i in x], expected, width, label='Expected', alpha=0.8)
        ax4.bar([i + width/2 for i in x], actual, width, label='Actual', alpha=0.8)
        ax4.set_xlabel('Worker')
        ax4.set_ylabel('Success Rate (%)')
        ax4.set_title('Expected vs Actual Performance')
        ax4.set_xticks(x)
        ax4.set_xticklabels(names, rotation=45, ha='right')
        ax4.legend()
        ax4.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        print(f"Saved plot to: {output_path}")
    else:
        plt.savefig('simulator_results.png', dpi=150, bbox_inches='tight')
        print("Saved plot to: simulator_results.png")

def print_summary(data):
    """Print text summary of results"""
    print("\n" + "="*70)
    print("SIMULATOR RESULTS SUMMARY")
    print("="*70)
    
    scenario = data.get('scenario', 'Unknown')
    print(f"\nScenario: {scenario}")
    print(f"Iterations: {data.get('iterations', 'N/A')}")
    
    validation = data.get('validation', {})
    print("\nValidation Results:")
    print(f"  Converged: {'✓' if validation.get('converged') else '✗'}")
    print(f"  Convergence Iteration: {validation.get('convergence_iteration', 'N/A')}")
    print(f"  Assignment Stability: {validation.get('assignment_stability', 0) * 100:.1f}%")
    print(f"  Exploration Rate: {validation.get('exploration_rate', 0) * 100:.1f}%")
    print(f"  Success Improvement: {validation.get('success_improvement', 0) * 100:.1f}%")
    print(f"  Latency Improvement: {validation.get('latency_improvement', 0) * 100:.1f}%")
    print(f"  All Agents Explored: {'✓' if validation.get('all_agents_explored') else '✗'}")
    print(f"  Overall: {'✓ PASS' if validation.get('all_passed') else '✗ FAIL'}")
    
    workers = data.get('workers', [])
    if workers:
        print("\nWorker Performance:")
        print(f"{'Name':<15} {'Expected':<12} {'Actual':<12} {'Executions':<12}")
        print("-" * 51)
        for w in workers:
            name = w.get('name', f"Agent {w.get('id', '?')}")
            expected = w.get('expected_success', 0) * 100
            actual = w.get('actual_success_rate', 0) * 100
            execs = w.get('actual_executions', 0)
            print(f"{name:<15} {expected:>10.1f}% {actual:>10.1f}% {execs:>10}")

def main():
    parser = argparse.ArgumentParser(description='Visualize Learning Simulator Results')
    parser.add_argument('input', help='Input file (CSV or JSON)')
    parser.add_argument('--output', '-o', help='Output plot file (PNG)')
    parser.add_argument('--summary', '-s', action='store_true', help='Print text summary only')
    args = parser.parse_args()
    
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: File not found: {input_path}")
        sys.exit(1)
    
    # Load data based on file extension
    if input_path.suffix == '.json':
        data = load_json(input_path)
    elif input_path.suffix == '.csv':
        data = load_csv(input_path)
    else:
        print(f"Error: Unsupported file format: {input_path.suffix}")
        print("Supported formats: .json, .csv")
        sys.exit(1)
    
    # Print summary
    print_summary(data)
    
    # Generate plot unless summary-only mode
    if not args.summary:
        plot_convergence(data, args.output)

if __name__ == '__main__':
    main()
