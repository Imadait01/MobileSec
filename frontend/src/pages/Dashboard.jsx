import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import apkScannerService from '../services/apkScanner';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { formatDate, getStatusColor } from '../utils/formatters';
import { useSettings } from '../context/SettingsContext';

const Dashboard = () => {
    const { t } = useSettings();
    const [stats, setStats] = useState(null);
    const [recentScans, setRecentScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                // Fetch stats and scans with error handling
                let statsData = null;
                let scansData = [];

                try {
                    const statsRes = await apkScannerService.getStats();
                    statsData = statsRes.data;
                } catch (statsErr) {
                    console.warn("Stats endpoint not available, using defaults:", statsErr.message);
                    // Use defaults if stats endpoint doesn't exist
                    statsData = { total_scans: 0, completed: 0, failed: 0 };
                }

                try {
                    const scansRes = await apkScannerService.getAllResults(5);
                    scansData = Array.isArray(scansRes.data) ? scansRes.data : scansRes.data.results || scansRes.data.items || [];
                } catch (scansErr) {
                    console.warn("Scans endpoint error:", scansErr.message);
                    scansData = [];
                }

                setStats(statsData);
                setRecentScans(scansData);
            } catch (err) {
                console.error("Dashboard error:", err);
                setError("Failed to load dashboard data");
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, []);

    if (loading) return <LoadingSpinner />;
    if (error) return <div className="text-red-500 p-4">{error}</div>;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h2 className="text-2xl font-bold text-slate-800 dark:text-white">{t('dashboard')}</h2>
                <Link to="/upload" className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition shadow-lg shadow-green-900/20">
                    + {t('new_scan')}
                </Link>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card className="border-l-4 border-l-blue-500">
                    <p className="text-slate-500 dark:text-slate-400 text-sm uppercase">{t('total_scans')}</p>
                    <p className="text-3xl font-bold text-slate-800 dark:text-white mt-1">{stats?.total_scans || 0}</p>
                </Card>
                <Card className="border-l-4 border-l-green-500">
                    <p className="text-slate-500 dark:text-slate-400 text-sm uppercase">{t('completed')}</p>
                    <p className="text-3xl font-bold text-slate-800 dark:text-white mt-1">{stats?.completed || stats?.completed_scans || 0}</p>
                </Card>
                <Card className="border-l-4 border-l-red-500">
                    <p className="text-slate-500 dark:text-slate-400 text-sm uppercase">{t('failed')}</p>
                    <p className="text-3xl font-bold text-slate-800 dark:text-white mt-1">{stats?.failed || stats?.failed_scans || 0}</p>
                </Card>
            </div>

            {/* Recent Scans Table */}
            <Card title={t('recent_scans')}>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700 text-sm">
                                <th className="pb-3 pl-2">{t('filename')}</th>
                                <th className="pb-3">{t('date')}</th>
                                <th className="pb-3">{t('status')}</th>
                                <th className="pb-3">{t('actions')}</th>
                            </tr>
                        </thead>
                        <tbody className="text-slate-600 dark:text-slate-300">
                            {recentScans.length === 0 ? (
                                <tr>
                                    <td colSpan="4" className="text-center py-4 text-slate-500">{t('no_scans')}</td>
                                </tr>
                            ) : (
                                recentScans.map((scan) => (
                                    <tr key={scan.scan_id} className="border-b border-slate-200 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition">
                                        <td className="py-3 pl-2 font-medium text-slate-800 dark:text-white max-w-[200px]">
                                            <div className="truncate" title={scan.results?.apk_name || scan.results?.file_name || scan.app_name}>
                                                {scan.results?.apk_name || scan.results?.file_name || scan.app_name || 'Unknown.apk'}
                                            </div>
                                        </td>
                                        <td className="py-3 whitespace-nowrap">{formatDate(scan.created_at || scan.results?.scan_timestamp || scan.timestamp)}</td>
                                        <td className="py-3 whitespace-nowrap">
                                            <Badge type={getStatusColor(scan.status)}>{scan.status}</Badge>
                                        </td>
                                        <td className="py-3 whitespace-nowrap">
                                            <Link
                                                to={`/scans/${scan.scan_id}`}
                                                className="text-blue-500 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 text-sm font-medium"
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

export default Dashboard;
