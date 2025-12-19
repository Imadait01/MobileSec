import React from 'react';
import Card from '../common/Card';
import Badge from '../common/Badge';

const CryptoAnalysis = ({ data }) => {
    // Adapter selon structure CryptoCheck
    const vulns = data?.vulnerabilities || data?.results || [];

    if (!vulns || vulns.length === 0) {
        return (
            <Card>
                <div className="text-center py-8">
                    <p className="text-green-500 font-medium text-lg">No cryptographic issues found. 🔐</p>
                </div>
            </Card>
        );
    }

    return (
        <div className="space-y-4">
            {vulns.map((vuln, index) => (
                <div key={index} className="bg-slate-800 rounded-lg p-5 border border-slate-700">
                    <div className="flex justify-between items-start">
                        <h4 className="font-bold text-yellow-400 text-lg">{vuln.type || 'Weak Cryptography'}</h4>
                        <Badge type="warning">{vuln.severity || 'Medium'}</Badge>
                    </div>

                    <p className="text-slate-300 mt-2">{vuln.description}</p>

                    <div className="mt-4 bg-slate-950 p-3 rounded border border-slate-800 font-mono text-sm">
                        <div className="text-slate-500 mb-1">
                            {vuln.file}:{vuln.line}
                        </div>
                        <code className="text-red-300">{vuln.code_snippet}</code>
                    </div>

                    <div className="mt-4">
                        <p className="text-sm font-semibold text-green-400">Recommendation:</p>
                        <p className="text-sm text-slate-400">{vuln.recommendation || 'Upgrade to a stronger algorithm (e.g. AES-256, SHA-256).'}</p>
                    </div>
                </div>
            ))}
        </div>
    );
};

export default CryptoAnalysis;
