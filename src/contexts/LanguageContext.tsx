/* eslint-disable react-refresh/only-export-components */
import React, { createContext, useContext, useEffect, useState } from 'react';
import { en, Translations } from '../locales/en';
import { ar } from '../locales/ar';

type Language = 'en' | 'ar';

interface LanguageContextType {
    language: Language;
    t: Translations;
    toggleLanguage: () => void;
    setLanguage: (lang: Language) => void;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [language, setLanguageState] = useState<Language>(() => {
        const savedLang = localStorage.getItem('safeweb_lang') as Language;
        if (savedLang === 'en' || savedLang === 'ar') {
            return savedLang;
        }
        return 'en';
    });

    useEffect(() => {
        document.documentElement.lang = language;
        document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr';
        localStorage.setItem('safeweb_lang', language);
    }, [language]);

    const toggleLanguage = () => {
        setLanguageState((prev) => (prev === 'en' ? 'ar' : 'en'));
    };

    const setLanguage = (newLang: Language) => {
        setLanguageState(newLang);
    };

    const t = language === 'ar' ? ar : en;

    return (
        <LanguageContext.Provider value={{ language, t, toggleLanguage, setLanguage }}>
            {children}
        </LanguageContext.Provider>
    );
};

export const useLanguage = (): LanguageContextType => {
    const context = useContext(LanguageContext);
    if (!context) {
        throw new Error('useLanguage must be used within a LanguageProvider');
    }
    return context;
};
