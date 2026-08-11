# Framework-specific offline trials

Each script runs one normal action and one hostile action in `local_sim` mode. No account, key, network connection, or third-party framework install is required.

```bash
python examples/frameworks/crewai.py
python examples/frameworks/langgraph.py
python examples/frameworks/mcp.py
```

The common runner forces offline mode and removes live credentials for the demonstration process. The printed “Production integration import” is the framework-specific attachment to use when moving to a live tenant sidecar. See the [examples guide](../README.md) for the complete framework/install matrix and the boundary between simulation and real enforcement.

For production, do not stop at the printed import. Follow the [production integration playbook](../PRODUCTION_INTEGRATION.md), then use the linked framework-native example in the main SDK README. The playbook identifies the exact construction file, first public attachment call, sensitive tool boundary and bypasses that must be removed for each framework.
