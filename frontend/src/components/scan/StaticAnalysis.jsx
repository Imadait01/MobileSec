import React from 'react';
import Card from '../common/Card';
import Badge from '../common/Badge';

const StaticAnalysis = ({ data }) => {
    if (!data) return <div className="text-slate-400">No static analysis data available.</div>;

    return (
        <div className="space-y-6">
            <Card title="Application Info">
                <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-6">
                    <div>
                        <dt className="text-sm font-medium text-slate-400">Package Name</dt>
                        <dd className="mt-1 text-lg font-semibold text-white">{data.package_name || 'N/A'}</dd>
                    </div>
                    <div>
                        <dt className="text-sm font-medium text-slate-400">Version</dt>
                        <dd className="mt-1 text-lg font-semibold text-white">{data.version_name || 'N/A'} ({data.version_code})</dd>
                    </div>
                    <div className="md:col-span-2">
                        <dt className="text-sm font-medium text-slate-400">SHA256</dt>
                        <dd className="mt-1 text-sm font-mono text-slate-300 break-all">{data.sha256 || 'N/A'}</dd>
                    </div>
                </dl>
            </Card>

            <Card title={`Permissions (${data.permissions?.length || 0})`}>
                <div className="space-y-2">
                    {data.permissions && data.permissions.length > 0 ? (
                        data.permissions.map((perm, index) => {
                            // Handle both string and object formats
                            const permName = typeof perm === 'string' ? perm : perm.name;
                            const isDangerous = typeof perm === 'object'
                                ? (perm.is_dangerous || perm.level === 'DANGEROUS')
                                : (perm.includes('DANGEROUS') || perm.includes('READ_CONTACTS') || perm.includes('LOCATION'));

                            return (
                                <div key={index} className="flex items-center justify-between p-3 bg-slate-800 rounded-lg">
                                    <span className="text-sm text-slate-300 font-mono break-all">{permName}</span>
                                    {isDangerous ? (
                                        <Badge type="danger">Dangerous</Badge>
                                    ) : (
                                        <Badge type="neutral">Normal</Badge>
                                    )}
                                </div>
                            );
                        })
                    ) : (
                        <p className="text-slate-500">No permissions found.</p>
                    )}
                </div>
            </Card>
        </div>
    );
};

export default StaticAnalysis;
