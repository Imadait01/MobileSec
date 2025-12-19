import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import reportGenService from '../services/reportGen';
import Badge from '../components/common/Badge';
import LoadingSpinner from '../components/common/LoadingSpinner';

const ReportsList = () => {
    const [reports, setReports] = useState([]);
    const [loading, setLoading] = useState(true);
    const [pagination, setPagination] = useState({ page: 1, total: 0, limit: 10 });
    const [deleting, setDeleting] = useState(null);

    useEffect(() => {
        fetchReports();
    }, [pagination.page]);

    const fetchReports = async () => {
        try {
            setLoading(true);
            const res = await reportGenService.getAllReports(pagination.page, pagination.limit);
            setReports(res.data.data);
            setPagination(prev => ({ ...prev, total: res.data.total }));
        } catch (error) {
            console.error("Failed to fetch reports", error);
            // alert("Debug: Failed to fetch reports. See console."); // Optional debug
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (reportId) => {
        if (!window.confirm("Are you sure you want to delete this report?")) return;

        try {
            setDeleting(reportId);
            await reportGenService.deleteReport(reportId);
            setReports(prev => prev.filter(r => r.reportId !== reportId));
        } catch (error) {
            console.error("Failed to delete report", error);
            alert("Failed to delete report.");
        } finally {
            setDeleting(null);
        }
    };

    const handleDownload = (reportId) => {
        const url = reportGenService.getDownloadUrl(reportId);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `report-${reportId}.pdf`);
        document.body.appendChild(link);
        link.click();
        link.remove();
    };

    if (loading && reports.length === 0) return <LoadingSpinner />;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-2xl font-bold text-white">Reports History</h1>
                    <p className="text-slate-400">Manage your generated security reports</p>
                </div>
                <button onClick={fetchReports} className="bg-slate-800 hover:bg-slate-700 text-white px-3 py-1 rounded text-sm transition">
                    🔄 Refresh
                </button>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-slate-950 text-slate-400 border-b border-slate-800 text-xs uppercase tracking-wider">
                                <th className="p-4 font-semibold">Generated Date</th>
                                <th className="p-4 font-semibold">Project Name</th>
                                <th className="p-4 font-semibold">Scan Source</th>
                                <th className="p-4 font-semibold">Status</th>
                                <th className="p-4 font-semibold text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                            {reports.length === 0 ? (
                                <tr>
                                    <td colSpan="5" className="p-8 text-center text-slate-500 italic">
                                        No reports found. Generate one from a scan detail page.
                                    </td>
                                </tr>
                            ) : (
                                reports.map((report) => (
                                    <tr key={report.reportId} className="text-sm hover:bg-slate-800/50 transition">
                                        <td className="p-4 text-slate-300">
                                            {new Date(report.generatedAt).toLocaleString()}
                                        </td>
                                        <td className="p-4 font-medium text-white">
                                            {report.projectName || 'Untitled'}
                                        </td>
                                        <td className="p-4 text-slate-400 font-mono text-xs">
                                            {report.scanId ? <Link to={`/scan/${report.scanId}`} className="hover:text-blue-400 underline decoration-dotted">{report.scanId.substring(0, 8)}...</Link> : '-'}
                                        </td>
                                        <td className="p-4">
                                            <Badge type={report.status === 'completed' ? 'safe' : report.status === 'failed' ? 'critical' : 'warning'}>
                                                {report.status}
                                            </Badge>
                                        </td>
                                        <td className="p-4 text-right space-x-2">
                                            <button
                                                onClick={() => window.open(reportGenService.getViewUrl(report.reportId), '_blank')}
                                                className="text-green-400 hover:text-green-300 transition mr-3"
                                                title="View Report"
                                            >
                                                👁️ View
                                            </button>
                                            <button
                                                onClick={() => handleDownload(report.reportId)}
                                                className="text-blue-400 hover:text-blue-300 transition"
                                                title="Download PDF"
                                            >
                                                ⬇️ PDF
                                            </button>
                                            <button
                                                onClick={() => handleDelete(report.reportId)}
                                                className="text-red-400 hover:text-red-300 transition ml-3"
                                                disabled={deleting === report.reportId}
                                                title="Delete Report"
                                            >
                                                {deleting === report.reportId ? '...' : '🗑️'}
                                            </button>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>

                {/* Pagination */}
                {pagination.total > pagination.limit && (
                    <div className="p-4 border-t border-slate-800 flex justify-between items-center text-sm text-slate-400">
                        <span>Showing {(pagination.page - 1) * pagination.limit + 1} to {Math.min(pagination.page * pagination.limit, pagination.total)} of {pagination.total}</span>
                        <div className="flex gap-2">
                            <button
                                disabled={pagination.page === 1}
                                onClick={() => setPagination(p => ({ ...p, page: p.page - 1 }))}
                                className="px-3 py-1 bg-slate-800 rounded hover:bg-slate-700 disabled:opacity-50"
                            >
                                Previous
                            </button>
                            <button
                                disabled={pagination.page * pagination.limit >= pagination.total}
                                onClick={() => setPagination(p => ({ ...p, page: p.page + 1 }))}
                                className="px-3 py-1 bg-slate-800 rounded hover:bg-slate-700 disabled:opacity-50"
                            >
                                Next
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ReportsList;
