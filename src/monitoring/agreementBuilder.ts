export function buildAgreementTTL(params) {
  return `
@prefix dpv: <https://www.w3.org/ns/dpv#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#agreement>
  a dpv:Consent ;
  dpv:hasDataSubject <${params.webId}> ;
  dpv:hasRecipient <client:${params.clientId}> ;
  dpv:hasProcessing dpv:${params.permission} ;
  dpv:hasPersonalData ${params.data.join(', ')} ;
  dpv:hasRisk dpv:${params.risk}Risk .
`;
}
