import React from 'react';
import Card from '../common/Card';
import Badge from '../common/Badge';

const SecretsAnalysis = ({ data }) => {
    // Adapter selon la structure réelle retournée par SecretHunter
    const secrets = data?.secrets || data?.results || data?.findings || [];

    if (!secrets || secrets.length === 0) {
        return (
            <Card>
                <div className="text-center py-8">
                    <p className="text-green-500 font-medium text-lg">No secrets detected! 🎉</p>
                    <p className="text-slate-500">The application code appears clean.</p>
                </div>
            </Card>
        );
    }

    return (
        <div className="space-y-4">
            <Card title={`Secrets Detected (${secrets.length})`} className="border-red-500/20">
                <div className="space-y-4">
                    {secrets.map((secret, index) => (
                        <div key={index} className="bg-slate-800 rounded-lg p-4 border-l-4 border-red-500">
                            <div className="flex justify-between items-start mb-2">
                                <h4 className="font-bold text-red-400">{secret.rule_name || 'Secret Found'}</h4>
                                <Badge type="danger">Critical</Badge>
                            </div>

                            <div className="space-y-2 text-sm">
                                <div>
                                    <span className="text-slate-500">File: </span>
                                    <span className="text-slate-300 font-mono">{secret.file_path || 'Unknown'}</span>
                                </div>

                                {secret.matched_content && (
                                    <div className="mt-2 text-xs bg-slate-950 p-2 rounded border border-slate-700 font-mono overflow-x-auto">
                                        <code>{secret.matched_content}</code>
                                    </div>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            </Card>
        </div>
    );
};

export default SecretsAnalysis;
