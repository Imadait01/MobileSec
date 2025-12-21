import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import apkScannerService from '../services/apkScanner';
import Card from '../components/common/Card';
import { useSettings } from '../context/SettingsContext';

const Upload = () => {
    const { t } = useSettings();
    const [file, setFile] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [progress, setProgress] = useState(0);
    const [error, setError] = useState(null);
    const navigate = useNavigate();

    const handleFileChange = (e) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0]);
            setError(null);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setFile(e.dataTransfer.files[0]);
            setError(null);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!file) return;

        setUploading(true);
        setProgress(0);

        try {
            await apkScannerService.scanFile(file, false, (event) => {
                const percent = Math.round((event.loaded * 100) / event.total);
                setProgress(percent);
            });

            // Assuming response contains scan_id, but sometimes it doesn't in direct calls if not awaited properly or structure differs.
            // Actually the service returns the promise, we wait for it.
            // But let's restart: the service call returns response.
            // Wait, I missed capturing the response in this rewrite! fixing now.
            const response = await apkScannerService.scanFile(file, false, (event) => {
                const percent = Math.round((event.loaded * 100) / event.total);
                setProgress(percent);
            });

            const scanId = response.data.scan_id;
            setTimeout(() => {
                navigate(`/scans/${scanId}`);
            }, 1000);

        } catch (err) {
            console.error("Upload failed", err);
            setError("Upload failed. Please try again.");
            setUploading(false);
        }
    };

    return (
        <div className="max-w-3xl mx-auto">
            <h2 className="text-2xl font-bold text-slate-800 dark:text-white mb-6">{t('new_scan')}</h2>

            <Card className="p-10 text-center">
                <div
                    className={`border-2 border-dashed rounded-xl p-12 transition-colors cursor-pointer ${file ? 'border-green-500/50 bg-green-500/5' : 'border-slate-300 dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                        }`}
                    onDrop={handleDrop}
                    onDragOver={handleDragOver}
                >
                    {!file ? (
                        <div className="space-y-4">
                            <div className="text-4xl">📤</div>
                            <h3 className="text-xl font-medium text-slate-800 dark:text-white">Drag & Drop your APK here</h3>
                            <p className="text-slate-500 dark:text-slate-400">or click below to browse</p>

                            <input
                                type="file"
                                id="fileInput"
                                accept=".apk"
                                className="hidden"
                                onChange={handleFileChange}
                            />
                            <label
                                htmlFor="fileInput"
                                className="inline-block bg-slate-200 hover:bg-slate-300 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-800 dark:text-white px-6 py-2 rounded-lg transition cursor-pointer"
                            >
                                Browse Files
                            </label>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            <div className="text-4xl">📄</div>
                            <h3 className="text-xl font-medium text-slate-800 dark:text-white">{file.name}</h3>
                            <p className="text-slate-500 dark:text-slate-400">{(file.size / (1024 * 1024)).toFixed(2)} MB</p>

                            {!uploading && (
                                <button
                                    onClick={() => setFile(null)}
                                    className="text-red-500 hover:text-red-600 dark:text-red-400 dark:hover:text-red-300 text-sm underline"
                                >
                                    Remove file
                                </button>
                            )}
                        </div>
                    )}
                </div>

                {uploading && (
                    <div className="mt-8 space-y-2">
                        <div className="flex justify-between text-sm text-slate-600 dark:text-slate-300">
                            <span>Uploading & Analyzing...</span>
                            <span>{progress}%</span>
                        </div>
                        <div className="w-full bg-slate-200 dark:bg-slate-800 rounded-full h-2.5 overflow-hidden">
                            <div
                                className="bg-green-500 h-2.5 rounded-full transition-all duration-300"
                                style={{ width: `${progress}%` }}
                            ></div>
                        </div>
                    </div>
                )}

                {error && (
                    <div className="mt-6 p-4 bg-red-500/10 text-red-500 rounded-lg">
                        {error}
                    </div>
                )}

                {!uploading && file && (
                    <div className="mt-8">
                        <button
                            onClick={handleSubmit}
                            className="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-6 rounded-lg transition shadow-lg shadow-green-900/20"
                        >
                            Start Analysis
                        </button>
                    </div>
                )}
            </Card>
        </div>
    );
};

export default Upload;
