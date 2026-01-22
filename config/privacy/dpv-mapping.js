/**
 * Mapping internal data keys to DPV Personal Data vocabulary
 * Source: https://www.w3.org/ns/dpv/pd#
 */
export const DPV_MAPPING = {
  nik: {
    label: "National Identification Number",
    dpv: "dpv-pd:NationalIdentificationNumber",
    category: "dpv:HighlySensitivePersonalData",
    domain: "identity"
  },

  bloodType: {
    label: "Blood Type",
    dpv: "dpv-pd:BloodType",
    category: "dpv:SpecialCategoryPersonalData",
    domain: "health"
  }
};
