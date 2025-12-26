import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import apkScannerService from '../services/apkScanner';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { formatDate, getStatusColor, formatBytes } from '../utils/formatters';
import { useSettings } from '../context/SettingsContext';

const Scans = () => {
    const { t } = useSettings();
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        loadScans();
    }, []);

    const loadScans = async () => {
        try {
            setLoading(true);
            setError(null);
            const response = await apkScannerService.getAllResults(100); // Higher limit
            // Adapter structure
            const scanData = Array.isArray(response.data) ? response.data : response.data.results || response.data.items || [];
            setScans(scanData);

            if (scanData.length === 0) {
                console.warn("No scans found in response");
            }
        } catch (err) {
            console.error("Error loading scans:", err);
            // Show more helpful error message
            if (err.response) {
                setError(`Failed to load scans: ${err.response.status} - ${err.response.statusText}`);
            } else if (err.request) {
                setError("Failed to load scans: Cannot connect to APK Scanner service. Please ensure all services are running.");
            } else {
                setError(`Failed to load scans: ${err.message}`);
            }
        } finally {
            setLoading(false);
        }
    };

    if (loading) return <LoadingSpinner />;
    if (error) return <div className="text-red-500 p-4">{error}</div>;

    return (
        <div className="space-y-6">
            <h2 className="text-2xl font-bold text-slate-800 dark:text-white">{t('scan_history')}</h2>

            <Card>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700 text-sm">
                                <th className="pb-3 pl-2">{t('filename')}</th>
                                <th className="pb-3">Size</th>
                                <th className="pb-3">{t('date')}</th>
                                <th className="pb-3">{t('status')}</th>
                                <th className="pb-3">{t('actions')}</th>
                            </tr>
                        </thead>
                        <tbody className="text-slate-600 dark:text-slate-300">
                            {scans.length === 0 ? (
                                <tr>
                                    <td colSpan="5" className="text-center py-8 text-slate-500">{t('no_scans')}</td>
                                </tr>
                            ) : (
                                scans.map((scan) => (
                                    <tr key={scan.scan_id} className="border-b border-slate-200 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition">
                                        <td className="py-4 pl-2 font-medium text-slate-800 dark:text-white max-w-xs sm:max-w-md">
                                            <div className="flex items-center">
                                                <span className="mr-3 text-xl flex-shrink-0">📱</span>
                                                <span className="truncate" title={scan.results?.apk_name || scan.results?.file_name || scan.app_name}>
                                                    {scan.results?.apk_name || scan.results?.file_name || scan.app_name || 'Unknown.apk'}
                                                </span>
                                            </div>
                                        </td>
                                        <td className="py-4 font-mono text-sm whitespace-nowrap">{formatBytes(scan.results?.file_size || 0)}</td>
                                        <td className="py-4 whitespace-nowrap">{formatDate(scan.created_at || scan.results?.scan_timestamp || scan.timestamp)}</td>
                                        <td className="py-4 whitespace-nowrap">
                                            <Badge type={getStatusColor(scan.status)}>{scan.status}</Badge>
                                        </td>
                                        <td className="py-4 whitespace-nowrap">
                                            <Link
                                                to={`/scans/${scan.scan_id}`}
                                                className="bg-slate-200 hover:bg-slate-300 text-slate-800 dark:bg-slate-700 dark:hover:bg-slate-600 dark:text-white px-3 py-1.5 rounded-md text-sm transition"
                                            >
                                                {t('view_details')}
                                            </Link>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
};

export default Scans;
