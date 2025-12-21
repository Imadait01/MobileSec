import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import fixSuggestService from '../services/fixSuggest';
import Layout from '../components/layout/Layout';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';

// Helper pour afficher le code avec une syntaxe basique
const CodeBlock = ({ code, language = 'java' }) => (
    <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm overflow-x-auto my-2 border border-gray-700">
        <div className="flex justify-between items-center mb-2 text-gray-400 text-xs">
            <span className="uppercase">{language}</span>
            <button
                onClick={() => navigator.clipboard.writeText(code)}
                className="hover:text-white transition-colors"
            >
                Copy
            </button>
        </div>
        <pre className="text-gray-300">
            <code>{code}</code>
        </pre>
    </div>
);

const FixSuggestions = () => {
    const { scanId } = useParams();
    const [loading, setLoading] = useState(true);
    const [regenerating, setRegenerating] = useState(false);
    const [error, setError] = useState(null);
    const [data, setData] = useState(null);

    const fetchSuggestions = async (forceRegenerate = false) => {
        try {
            setLoading(true);
            if (forceRegenerate) setRegenerating(true);

            // Essayer d'abord le cache si on ne force pas
            let response;
            if (!forceRegenerate) {
                try {
                    response = await fixSuggestService.getCachedSuggestions(scanId);
                } catch (e) {
                    // Cache miss, generate
                    response = await fixSuggestService.getSuggestions(scanId, false);
                }
            } else {
                response = await fixSuggestService.getSuggestions(scanId, true);
            }

            setData(response);
            setError(null);
        } catch (err) {
            console.error(err);
            setError('Impossible de charger les suggestions. Le service est peut-être indisponible.');
        } finally {
            setLoading(false);
            setRegenerating(false);
        }
    };

    useEffect(() => {
        fetchSuggestions();
    }, [scanId]);

    const getConfidenceBadge = (score) => {
        // Score entre 0 et 1 ? ou 0 et 100? main.py example shows 0.95
        const s = score <= 1 ? score * 100 : score;
        if (s >= 80) return <Badge type="success">High Confidence ({s}%)</Badge>;
        if (s >= 50) return <Badge type="warning">Medium Confidence ({s}%)</Badge>;
        return <Badge type="danger">Low Confidence ({s}%)</Badge>;
    };

    return (
        <Layout title="AI Fix Suggestions">
            <div className="mb-6 flex justify-between items-center">
                <div>
                    <Link to={`/scans/${scanId}`} className="text-blue-500 hover:underline mb-2 inline-block">
                        &larr; Back to Scan Details
                    </Link>
                    <h1 className="text-3xl font-bold text-white">
                        Intelligent Patch Suggestions <span className="text-purple-400">✨ AI Powered</span>
                    </h1>
                    <p className="text-gray-400 mt-1">
                        Automated analysis and code fixes powered by Amazon Nova 2 Lite
                    </p>
                </div>
                <button
                    onClick={() => fetchSuggestions(true)}
                    disabled={regenerating || loading}
                    className={`px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 ${regenerating
                            ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                            : 'bg-purple-600 hover:bg-purple-700 text-white'
                        }`}
                >
                    {regenerating ? (
                        <>
                            <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Regenerating...
                        </>
                    ) : (
                        <>
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                            Regenerate Suggestions
                        </>
                    )}
                </button>
            </div>

            {loading && !data && (
                <div className="text-center py-20">
                    <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-purple-500 mx-auto mb-4"></div>
                    <p className="text-gray-400">Analysis in progress... This may take a few seconds.</p>
                </div>
            )}

            {error && !data && (
                <Card className="border-red-500 border">
                    <div className="text-red-500 text-center py-8">
                        <svg className="w-12 h-12 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                        <h3 className="text-xl font-bold">Analysis Failed</h3>
                        <p className="mt-2 text-gray-300">{error}</p>
                        <p className="mt-4 text-sm text-gray-500">Ensure the FixSuggest service is running and configured.</p>
                    </div>
                </Card>
            )}

            {data && (
                <div className="space-y-6">
                    {/* Summary Metrics */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <Card>
                            <div className="text-gray-400 text-sm uppercase tracking-wider">Total Suggestions</div>
                            <div className="text-3xl font-bold text-white mt-1">{data.suggestions_count || 0}</div>
                        </Card>
                        <Card>
                            <div className="text-gray-400 text-sm uppercase tracking-wider">Model Used</div>
                            <div className="text-xl font-bold text-purple-400 mt-1 truncate" title={data.model_used}>{data.model_used || 'N/A'}</div>
                        </Card>
                        <Card>
                            <div className="text-gray-400 text-sm uppercase tracking-wider">Generated At</div>
                            <div className="text-lg text-white mt-1">
                                {data.generated_at ? new Date(data.generated_at).toLocaleString() : 'Just now'}
                            </div>
                        </Card>
                    </div>

                    {/* Suggestions List */}
                    {data.suggestions && data.suggestions.length > 0 ? (
                        data.suggestions.map((item, index) => (
                            <Card key={index} className="border border-gray-800 hover:border-purple-900 transition-colors">
                                <div className="flex justify-between items-start mb-4">
                                    <div>
                                        <h3 className="text-xl font-bold text-white flex items-center gap-2">
                                            <span className="text-purple-400">#{index + 1}</span> {item.masvs_title || 'Security Issue'}
                                        </h3>
                                        <div className="flex items-center gap-2 mt-1">
                                            <Badge type="info">{item.masvs_category || 'General'}</Badge>
                                            <span className="text-gray-500 text-sm">Vulnerability ID: {item.vulnerability_id}</span>
                                        </div>
                                    </div>
                                    {getConfidenceBadge(item.confidence)}
                                </div>

                                <div className="prose prose-invert max-w-none">
                                    <h4 className="text-gray-300 font-semibold mt-4 mb-2">Analysis & Explanation</h4>
                                    <p className="text-gray-400 whitespace-pre-wrap">{item.explanation}</p>

                                    {item.suggested_patch && (
                                        <>
                                            <h4 className="text-gray-300 font-semibold mt-6 mb-2">Recommended Fix</h4>
                                            <CodeBlock code={item.suggested_patch} />
                                        </>
                                    )}

                                    {item.references && item.references.length > 0 && (
                                        <div className="mt-4 pt-4 border-t border-gray-800">
                                            <span className="text-gray-500 text-sm font-semibold">References:</span>
                                            <div className="flex flex-wrap gap-2 mt-1">
                                                {item.references.map((ref, idx) => (
                                                    <a
                                                        key={idx}
                                                        href={ref}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="text-blue-400 hover:text-blue-300 text-sm underline truncate max-w-xs"
                                                    >
                                                        {ref}
                                                    </a>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </Card>
                        ))
                    ) : (
                        <div className="text-center py-10 text-gray-500">
                            No suggestions generated yet. Click "Regenerate" to start analysis.
                        </div>
                    )}
                </div>
            )}
        </Layout>
    );
};

export default FixSuggestions;
