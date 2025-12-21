import React from 'react';
import Card from '../common/Card';
import Badge from '../common/Badge';

const NetworkAnalysis = ({ data }) => {
    // Adapter selon la structure NetworkInspector
    // Structure MongoDB: { analysis: { security_issues: [], flows: [] } }
    const analysis = data?.analysis || {};
    const flows = analysis.flows || data.flows || [];
    const issues = analysis.security_issues || data.issues || [];

    if ((!flows || flows.length === 0) && (!issues || issues.length === 0)) {
        return (
            <Card>
                <div className="text-center py-8">
                    <p className="text-slate-400">No network issues or traffic detected.</p>
                    <p className="text-sm text-slate-500 mt-2">The application appears network-secure or inactive.</p>
                </div>
            </Card>
        );
    }

    return (
        <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card title="Traffic Summary">
                    <div className="flex justify-between items-center py-2 border-b border-slate-800">
                        <span className="text-slate-400">Total Requests</span>
                        <span className="text-white font-bold">{flows.length}</span>
                    </div>
                    <div className="flex justify-between items-center py-2">
                        <span className="text-slate-400">Insecure (HTTP)</span>
                        <span className="text-red-400 font-bold">
                            {flows.filter(f => f.scheme === 'http').length}
                        </span>
                    </div>
                </Card>

                <Card title="Static Analysis Issues">
                    <div className="flex justify-between items-center py-2 border-b border-slate-800">
                        <span className="text-slate-400">Potential Issues</span>
                        <span className="text-white font-bold">{issues.length}</span>
                    </div>
                    <div className="flex justify-between items-center py-2">
                        <span className="text-slate-400">High Severity</span>
                        <span className="text-red-400 font-bold">
                            {issues.filter(i => i.severity === 'High').length}
                        </span>
                    </div>
                </Card>
            </div>

            {/* Static Analysis List */}
            {issues.length > 0 && (
                <Card title="Static Security Issues">
                    <div className="space-y-3">
                        {issues.map((issue, idx) => (
                            <div key={idx} className="bg-slate-800 p-3 rounded border-l-4 border-yellow-500">
                                <h4 className="font-bold text-slate-200">{issue.title || 'Security Issue'}</h4>
                                <p className="text-sm text-slate-400 mt-1">{issue.description}</p>
                                <div className="mt-2 text-xs text-slate-500 font-mono">
                                    {issue.file_path}
                                </div>
                            </div>
                        ))}
                    </div>
                </Card>
            )}

            {/* Dynamic Traffic List */}
            {flows.length > 0 && (
                <Card title="Captured Traffic">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                            <thead className="bg-slate-800 text-slate-400">
                                <tr>
                                    <th className="p-3">Method</th>
                                    <th className="p-3">Host</th>
                                    <th className="p-3">Path</th>
                                    <th className="p-3">Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800">
                                {flows.map((flow, idx) => (
                                    <tr key={idx} className="hover:bg-slate-800/50">
                                        <td className="p-3">
                                            <Badge type={flow.method === 'GET' ? 'info' : 'warning'}>{flow.method}</Badge>
                                        </td>
                                        <td className="p-3 text-slate-300">{flow.host}</td>
                                        <td className="p-3 text-slate-400 font-mono truncate max-w-xs">{flow.path}</td>
                                        <td className="p-3">
                                            <span className={flow.response_code >= 400 ? 'text-red-400' : 'text-green-400'}>
                                                {flow.response_code}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </Card>
            )}
        </div>
    );
};

export default NetworkAnalysis;
