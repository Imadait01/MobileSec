import React, { useEffect, useState, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import apkScannerService from '../services/apkScanner';
import secretHunterService from '../services/secretHunter';
import networkInspectorService from '../services/networkInspector';
import cryptoCheckService from '../services/cryptoCheck';
import reportGenService from '../services/reportGen';


import Badge from '../components/common/Badge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import StaticAnalysis from '../components/scan/StaticAnalysis';
import SecretsAnalysis from '../components/scan/SecretsAnalysis';
import NetworkAnalysis from '../components/scan/NetworkAnalysis';
import CryptoAnalysis from '../components/scan/CryptoAnalysis';

import { formatDate, getStatusColor } from '../utils/formatters';

const ScanDetail = () => {
    const { id } = useParams();
    const [activeTab, setActiveTab] = useState('static');
    const [scanData, setScanData] = useState(null);
    const [results, setResults] = useState({
        static: null,
        secrets: null,
        network: null,
        crypto: null
    });
    const [errors, setErrors] = useState({
        secrets: null,
        network: null,
        crypto: null
    });
    const [loading, setLoading] = useState(true);
    const pollingRef = useRef(null);

    // Initial load
    useEffect(() => {
        loadScanDetails();

        // Start polling
        pollingRef.current = setInterval(loadScanDetails, 5000);

        return () => {
            if (pollingRef.current) clearInterval(pollingRef.current);
        };
    }, [id]);

    const loadScanDetails = async () => {
        try {
            // 1. Fetch APK Basic info
            const apkRes = await apkScannerService.getResults(id);
            const rawData = apkRes.data;

            // Normalize data: backend returns { status: "...", results: { apk_name: "...", ... } }
            // We want a flat structure or predictable access.
            const normalizedData = {
                ...rawData,
                ...(rawData.results || {}), // Merge inner results if present
                file_name: rawData.results?.apk_name || rawData.app_name || rawData.file_name || 'Unknown.apk',
                timestamp: rawData.created_at || rawData.timestamp
            };

            setScanData(normalizedData);
            setResults(prev => ({ ...prev, static: normalizedData }));

            // Stop polling only if explicitly completed and we have data
            if (normalizedData.status === 'completed' || normalizedData.status === 'failed') {
                // Check if we have all sub-results?
                // For now, relies on the individual service polls below
            }

            // 2. Fetch other services independently
            const endpoints = [
                { key: 'secrets', service: secretHunterService },
                { key: 'network', service: networkInspectorService },
                { key: 'crypto', service: cryptoCheckService }
            ];

            const promises = endpoints.map(async ({ key, service }) => {
                try {
                    const res = await service.getResults(id);
                    return { key, data: res.data, error: null };
                } catch (e) {
                    // Suppress 404s (pending analysis), report other errors
                    if (e.response && e.response.status === 404) {
                        return { key, data: null, error: null };
                    }
                    console.error(`Error fetching ${key}:`, e);
                    return { key, data: null, error: e.message || 'Fetch failed' };
                }
            });

            const responses = await Promise.all(promises);

            setResults(prev => {
                const next = { ...prev };
                let hasNewData = false;
                responses.forEach(({ key, data }) => {
                    if (data && JSON.stringify(data) !== JSON.stringify(prev[key])) {
                        next[key] = data;
                        hasNewData = true;
                    }
                });
                return hasNewData ? next : prev;
            });

            setErrors(prev => {
                const next = { ...prev };
                responses.forEach(({ key, error }) => {
                    next[key] = error; // Always update error status
                });
                return next;
            });

            // If we have all data, stop polling
            const allLoaded = responses.every(r => r.data !== null);
            if (allLoaded && normalizedData.status === 'completed') {
                if (pollingRef.current) clearInterval(pollingRef.current);
            }

        } catch (err) {
            console.error("Failed to load scan details", err);
        } finally {
            setLoading(false);
        }
    };

    const [downloading, setDownloading] = useState(false);

    const handleDownloadReport = async () => {
        try {
            setDownloading(true);
            // 1. Trigger report generation
            const res = await reportGenService.generateReport(id, 'pdf');

            if (res.data && res.data.reportId) {
                const reportId = res.data.reportId;

                // 2. Poll for completion
                let attempts = 0;
                const maxAttempts = 30; // 60s timeout

                const pollInterval = setInterval(async () => {
                    attempts++;
                    try {
                        const statusRes = await reportGenService.getReportStatus(reportId);
                        const status = statusRes.data.status;

                        // Stop if completed
                        if (status === 'completed') {
                            clearInterval(pollInterval);

                            // 3. Download
                            const downloadArgs = reportGenService.getDownloadUrl(reportId);
                            const link = document.createElement('a');
                            link.href = downloadArgs;
                            link.setAttribute('download', `report-${id}.pdf`);
                            document.body.appendChild(link);
                            link.click();
                            link.remove();

                            setDownloading(false);
                        }
                        // Stop if failed
                        else if (status === 'failed') {
                            clearInterval(pollInterval);
                            setDownloading(false);
                            alert("Report generation failed on server side.");
                        }
                        // Stop if timeout
                        else if (attempts >= maxAttempts) {
                            clearInterval(pollInterval);
                            setDownloading(false);
                            alert("Report generation timed out.");
                        }
                    } catch (e) {
                        console.error("Polling check failed", e);
                        // Don't stop polling for network blips
                    }
                }, 2000);
            } else {
                setDownloading(false);
                alert("Failed to get report ID.");
            }
        } catch (error) {
            console.error("Report generation trigger failed:", error);
            setDownloading(false);
            alert("Failed to initiate report generation.");
        }
    };

    if (loading && !scanData) return <LoadingSpinner />;
    if (!loading && !scanData) return <div className="text-red-500 text-center mt-10">Scan not found.</div>;

    const tabs = [
        { id: 'static', label: 'Static Analysis', icon: '📦' },
        { id: 'secrets', label: 'Secrets', icon: '🔑' },
        { id: 'network', label: 'Network', icon: '🌐' },
        { id: 'crypto', label: 'Cryptography', icon: '🔐' },
    ];

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center">
                <div>
                    <div className="flex items-center gap-3">
                        <h2 className="text-2xl font-bold text-white">{scanData.file_name || 'Unknown.apk'}</h2>
                        <Badge type={getStatusColor(scanData.status)}>{scanData.status}</Badge>
                        {scanData.status === 'in_progress' && <span className="text-xs text-yellow-500 animate-pulse">Analyzing...</span>}
                    </div>
                    <p className="text-slate-400 mt-1 text-sm">
                        Scanned on {formatDate(scanData.timestamp || scanData.started_at)} • ID: <span className="font-mono text-slate-500">{id}</span>
                    </p>
                </div>

                <div className="mt-4 md:mt-0 flex gap-3">
                    <button
                        onClick={() => window.print()}
                        className="bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg transition text-sm"
                    >
                        🖨️ Print Report
                    </button>
                    <Link
                        to={`/scans/${id}/suggestions`}
                        className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition text-sm font-medium flex items-center gap-2"
                    >
                        ✨ AI Suggestions
                    </Link>
                    {/* Placeholder for PDF Download which implies calling ReportGen */}
                    <button
                        onClick={handleDownloadReport}
                        disabled={downloading}
                        className={`bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition text-sm font-medium flex items-center gap-2 ${downloading ? 'opacity-70 cursor-not-allowed' : ''}`}
                    >
                        {downloading ? (
                            <>
                                <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></span>
                                Generating...
                            </>
                        ) : (
                            <>
                                ⬇️ Download PDF
                            </>
                        )}
                    </button>
                </div>
            </div>

            {/* Tabs Navigation */}
            <div className="border-b border-slate-800">
                <nav className="-mb-px flex space-x-8">
                    {tabs.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`
                                py-4 px-1 border-b-2 font-medium text-sm flex items-center
                                ${activeTab === tab.id
                                    ? 'border-green-500 text-green-500'
                                    : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-700'
                                }
                            `}
                        >
                            <span className="mr-2">{tab.icon}</span>
                            {tab.label}
                        </button>
                    ))}
                </nav>
            </div>

            {/* Tab Content */}
            <div className="min-h-[400px]">
                {activeTab === 'static' && <StaticAnalysis data={results.static} />}
                {activeTab === 'secrets' && (
                    results.secrets ? <SecretsAnalysis data={results.secrets} /> :
                        <div className="p-8 text-center text-slate-500">
                            {scanData.status === 'in_progress' ? 'Scanning for secrets...' : 'Waiting for SecretHunter results...'}
                        </div>
                )}
                {activeTab === 'network' && (
                    results.network ? <NetworkAnalysis data={results.network} /> :
                        <div className="p-8 text-center text-slate-500">
                            {scanData.status === 'in_progress' ? 'Analyzing network traffic (approx 60s)...' : 'Waiting for NetworkInspector results...'}
                        </div>
                )}
                {activeTab === 'crypto' && (
                    results.crypto ? <CryptoAnalysis data={results.crypto} /> :
                        <div className="p-8 text-center text-slate-500">
                            {errors.crypto ? (
                                <span className="text-red-400">Error: {errors.crypto} (Check Console)</span>
                            ) : (
                                scanData.status === 'in_progress' ? 'Analyzing cryptography...' : 'Waiting for CryptoCheck results...'
                            )}
                        </div>
                )}
            </div>
        </div>
    );
};

export default ScanDetail;
