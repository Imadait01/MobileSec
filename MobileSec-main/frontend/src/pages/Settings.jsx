import React, { useState } from 'react';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';
import { useSettings } from '../context/SettingsContext';

const Settings = () => {
    const { theme, toggleTheme, language, changeLanguage, t } = useSettings();
    const [notifications, setNotifications] = useState(true);
    const [autoDelete, setAutoDelete] = useState(false);
    const [scanDuration, setScanDuration] = useState(60);

    return (
        <div className="space-y-6">
            <h2 className="text-2xl font-bold text-slate-800 dark:text-white">{t('settings')}</h2>

            {/* System Status */}
            <Card title={t('system_status')} className="border-l-4 border-l-blue-500">
                <div className="flex items-center justify-between mb-4">
                    <span className="text-slate-600 dark:text-slate-300">{t('api_connection')}</span>
                    <Badge type="success">{t('connected')}</Badge>
                </div>
                <div className="flex items-center justify-between mb-4">
                    <span className="text-slate-600 dark:text-slate-300">{t('database')}</span>
                    <Badge type="success">{t('online')}</Badge>
                </div>
                <div className="flex items-center justify-between">
                    <span className="text-slate-600 dark:text-slate-300">{t('version')}</span>
                    <span className="text-slate-500 dark:text-slate-400 font-mono">v1.2.0</span>
                </div>
            </Card>

            {/* Appearance & Language (NEW) */}
            <Card title={t('theme') + " & " + t('language')}>
                <div className="space-y-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <label className="block text-slate-800 dark:text-white font-medium">{t('theme')}</label>
                            <p className="text-sm text-slate-500">{theme === 'dark' ? t('dark_mode') : t('light_mode')}</p>
                        </div>
                        <button
                            onClick={toggleTheme}
                            className={`w-12 h-6 rounded-full p-1 transition-colors duration-200 ease-in-out ${theme === 'dark' ? 'bg-indigo-500' : 'bg-yellow-400'}`}
                        >
                            <div className={`w-4 h-4 bg-white rounded-full shadow-md transform transition-transform duration-200 ease-in-out ${theme === 'dark' ? 'translate-x-6' : 'translate-x-0'}`} />
                        </button>
                    </div>

                    <div className="flex items-center justify-between pt-4 border-t border-slate-200 dark:border-slate-700/50">
                        <div>
                            <label className="block text-slate-800 dark:text-white font-medium">{t('language')}</label>
                            <p className="text-sm text-slate-500">{language === 'en' ? 'English' : 'Français'}</p>
                        </div>
                        <div className="flex space-x-2">
                            <button
                                onClick={() => changeLanguage('en')}
                                className={`px-3 py-1 rounded transition ${language === 'en' ? 'bg-blue-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                            >
                                EN
                            </button>
                            <button
                                onClick={() => changeLanguage('fr')}
                                className={`px-3 py-1 rounded transition ${language === 'fr' ? 'bg-blue-600 text-white' : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}
                            >
                                FR
                            </button>
                        </div>
                    </div>
                </div>
            </Card>

            {/* Scanning Preferences */}
            <Card title={t('scanning_preferences')}>
                <div className="space-y-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <label className="block text-slate-800 dark:text-white font-medium">{t('default_duration')}</label>
                            <p className="text-sm text-slate-500">Maximum time (seconds) for dynamic analysis</p>
                        </div>
                        <input
                            type="number"
                            value={scanDuration}
                            onChange={(e) => setScanDuration(e.target.value)}
                            className="bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white rounded px-3 py-2 w-24 focus:outline-none focus:border-green-500"
                        />
                    </div>

                    <div className="flex items-center justify-between pt-4 border-t border-slate-200 dark:border-slate-700/50">
                        <div>
                            <label className="block text-slate-800 dark:text-white font-medium">{t('auto_delete')}</label>
                            <p className="text-sm text-slate-500">Delete scan results after 30 days</p>
                        </div>
                        <button
                            onClick={() => setAutoDelete(!autoDelete)}
                            className={`w-12 h-6 rounded-full p-1 transition-colors duration-200 ease-in-out ${autoDelete ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-700'}`}
                        >
                            <div className={`w-4 h-4 bg-white rounded-full shadow-md transform transition-transform duration-200 ease-in-out ${autoDelete ? 'translate-x-6' : 'translate-x-0'}`} />
                        </button>
                    </div>
                </div>
            </Card>

            {/* Notifications */}
            <Card title={t('notifications')}>
                <div className="flex items-center justify-between">
                    <div>
                        <label className="block text-slate-800 dark:text-white font-medium">{t('email_alerts')}</label>
                        <p className="text-sm text-slate-500">Receive emails when high-severity issues are found</p>
                    </div>
                    <button
                        onClick={() => setNotifications(!notifications)}
                        className={`w-12 h-6 rounded-full p-1 transition-colors duration-200 ease-in-out ${notifications ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-700'}`}
                    >
                        <div className={`w-4 h-4 bg-white rounded-full shadow-md transform transition-transform duration-200 ease-in-out ${notifications ? 'translate-x-6' : 'translate-x-0'}`} />
                    </button>
                </div>
            </Card>

            <div className="flex justify-end">
                <button className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded-lg font-medium transition shadow-lg shadow-green-900/20">
                    {t('save_changes')}
                </button>
            </div>
        </div>
    );
};

export default Settings;
