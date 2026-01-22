export const PRIVACY_POLICY = {
  personalData: {
    nik: {
      dpv: "dpv-pd:NationalIdentificationNumber",
      category: "dpv:HighlySensitivePersonalData",
      requiresExplicitConsent: true
    },
    bloodType: {
      dpv: "dpv-pd:BloodType",
      category: "dpv:SpecialCategoryPersonalData",
      requiresExplicitConsent: true
    }
  }
};
