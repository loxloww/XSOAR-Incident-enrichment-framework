from typing import List, Dict, Any
from abc import ABC, abstractmethod


# INCIDENT PARSER -> Abstract base for multi-SIEM

class IncidentParser(ABC):

    def __init__(self, incident: Dict[str, Any]):
        self.incident = incident

    @abstractmethod
    def parse(self) -> List[Dict[str, Any]]:
        # Parse incident -> extract IOCs normalized format
        # Returns: List[{'value': 'X.X.X.X', 'indicator_type': 'IP'}, ...]
        pass

# Sentinel SIEM parser
class SentinelParser(IncidentParser):

    def parse(self) -> List[Dict[str, Any]]:
        indicators = []

        try:
            import json

            custom_fields = self.incident.get('CustomFields', {})
            entities_raw = custom_fields.get('microsoftsentinelentities', [])

            # Parse if JSON string
            if isinstance(entities_raw, str):
                entities = json.loads(entities_raw)
            else:
                entities = entities_raw

            if not isinstance(entities, list):
                return indicators

            for entity in entities:
                if not isinstance(entity, dict):
                    continue

                entity_kind = entity.get('kind', '').lower()
                props = entity.get('properties', {})

                # IPs
                if entity_kind == 'ip':
                    ip = props.get('address') or props.get('Address')
                    if ip:
                        indicators.append({'value': ip, 'indicator_type': 'IP'})

                # URLs
                elif entity_kind == 'url':
                    url = props.get('url') or props.get('Url')
                    if url:
                        indicators.append({'value': url, 'indicator_type': 'URL'})

                # Domains / Hosts
                elif entity_kind in ['host', 'dnsresolution']:
                    domain = props.get('domainName') or props.get('DomainName') or props.get('hostName') or props.get('HostName')
                    if domain:
                        indicators.append({'value': domain, 'indicator_type': 'Domain'})

                # File hashes from file entity
                elif entity_kind == 'file':
                    for hash_field in ['fileHashSha256', 'FileHashSha256', 'sha256', 'fileHashSha1', 'FileHashSha1', 'sha1', 'fileHashMd5', 'FileHashMd5', 'md5']:
                        hash_val = props.get(hash_field)
                        if hash_val:
                            indicators.append({'value': hash_val, 'indicator_type': 'File'})
                            break  # one hash per file

                # File hashes from dedicated filehash entity
                elif entity_kind == 'filehash':
                    hash_val = props.get('hashValue') or props.get('HashValue')
                    if hash_val:
                        indicators.append({'value': hash_val, 'indicator_type': 'File'})

        except:
            pass

        return indicators

# Splunk / Generic SIEM parser
class SplunkParser(IncidentParser):

    def parse(self) -> List[Dict[str, Any]]:
        indicators = []

        inc_id = self.incident.get('id', '')
        if not inc_id:
            return indicators

        try:
            result = demisto.executeCommand("searchIndicators", {
                "query": f"incident.id:{inc_id}"
            })

            if isinstance(result, dict):
                iocs = result.get('iocs', [])
                for ioc in iocs:
                    if isinstance(ioc, dict):
                        indicators.append({
                            'value': ioc.get('value', ''),
                            'indicator_type': ioc.get('indicator_type', '') or ioc.get('type', '')
                        })
        except:
            pass

        return indicators


# IOC ENRICHER -> Multi-source threat intel

class IOCEnricher:

    def __init__(self):
        self.results = []

    def enrich(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched = []

        for ind in indicators:
            ind_type = ind.get('indicator_type', '')
            ind_value = ind.get('value', '')

            if not ind_value:
                continue

            result = {
                'value': ind_value,
                'type': ind_type,
                'score': 0,
                'verdict': 'UNKNOWN',
                'sources': []
            }

            # Route to correct enrichment function
            if ind_type in ['IP', 'IPv4']:
                result = self._enrich_ip(ind_value)
            elif ind_type == 'URL':
                result = self._enrich_url(ind_value)
            elif ind_type == 'Domain':
                result = self._enrich_domain(ind_value)
            elif ind_type in ['File', 'SHA256', 'SHA1', 'MD5']:
                result = self._enrich_file(ind_value)

            enriched.append(result)

        return enriched

    def _enrich_ip(self, ip: str) -> Dict[str, Any]:
        scores = []
        sources = []
        demisto.results(f"### DEBUG: Enriching IP {ip}")

        # Call ip command -> ALL integrations respond (VT, AbuseIPDB, OTX, etc.)
        try:
            ip_results = demisto.executeCommand("ip", {"ip": ip})
            if ip_results and isinstance(ip_results, list):
                demisto.results(f"### DEBUG: Got {len(ip_results)} results from ip command")

                # Loop through integration results
                for result in ip_results:
                    brand = result.get('Brand', 'Unknown')

                    # OTX disabled - error timeout to each request
                    # if 'AlienVault' in brand or 'OTX' in brand:
                    #     demisto.results(f"### DEBUG: SKIPPED {brand} - timeout")
                    #     continue

                    if result.get('Type') == 4:  # Error type
                        error_msg = result.get('Contents', 'Unknown error')
                        demisto.results(f"### DEBUG: SKIPPED {brand} - Error: {error_msg}")
                        continue

                    demisto.results(f"### DEBUG: Processing result from {brand}")

                    # Parse score (DBotScore standard)
                    score = self._parse_vt_ip(result)
                    demisto.results(f"### DEBUG: {brand} score for {ip} = {score}")

                    if score > 0:
                        scores.append(score)
                        sources.append(brand)
        except Exception as e:
            demisto.results(f"### DEBUG: IP enrichment error for {ip}: {str(e)}")

        avg_score = sum(scores) / len(scores) if scores else 0
        demisto.results(f"### DEBUG: Final score for {ip} = {int(avg_score)} from {len(sources)} sources: {', '.join(sources)}")

        return {
            'value': ip,
            'type': 'IP',
            'score': int(avg_score),
            'verdict': self._get_verdict(avg_score),
            'sources': sources if sources else ['No integrations available']
        }

    def _enrich_url(self, url: str) -> Dict[str, Any]:
        scores = []
        sources = []
        demisto.results(f"### DEBUG: Enriching URL {url}")

        # Call url command -> ALL integrations (VT, URLScan, GSB, OTX, etc.)
        try:
            url_results = demisto.executeCommand("url", {"url": url})
            if url_results and isinstance(url_results, list):
                demisto.results(f"### DEBUG: Got {len(url_results)} results from url command")

                for result in url_results:
                    brand = result.get('Brand', 'Unknown')

                    # OTX disabled - timeout issue
                    # if 'AlienVault' in brand or 'OTX' in brand:
                    #     demisto.results(f"### DEBUG: SKIPPED {brand} for URL - timeout")
                    #     continue

                    if result.get('Type') == 4:  # Skip errors
                        error_msg = result.get('Contents', 'Unknown error')
                        demisto.results(f"### DEBUG: SKIPPED {brand} for URL - Error: {error_msg}")
                        continue

                    demisto.results(f"### DEBUG: Processing URL result from {brand}")
                    score = self._parse_vt_url(result)  # DBotScore standard
                    demisto.results(f"### DEBUG: {brand} URL score = {score}")
                    if score > 0:
                        scores.append(score)
                        sources.append(brand)
        except Exception as e:
            demisto.results(f"### DEBUG: URL enrichment error: {str(e)}")

        avg_score = sum(scores) / len(scores) if scores else 0

        # Also enrich extracted domain from URL
        try:
            # Extract domain (remove protocol + path)
            domain = url
            if '://' in domain:
                domain = domain.split('://')[1]
            if '/' in domain:
                domain = domain.split('/')[0]

            # Get root domain
            root_domain = self._extract_root_domain(domain)
            demisto.results(f"### DEBUG: Also enriching domain {root_domain} extracted from URL {url}")

            domain_results = demisto.executeCommand("domain", {"domain": root_domain})
            if domain_results and isinstance(domain_results, list):
                demisto.results(f"### DEBUG: Got {len(domain_results)} results from domain command for {root_domain}")
                for result in domain_results:
                    brand = result.get('Brand', 'Unknown')
                    if result.get('Type') == 4:
                        continue

                    domain_score = self._parse_vt_domain(result)
                    demisto.results(f"### DEBUG: {brand} domain score for {root_domain} = {domain_score}")
                    if domain_score > 0:
                        scores.append(domain_score)
                        sources.append(f"{brand} (domain)")

                # Recalculate avg with domain scores
                avg_score = sum(scores) / len(scores) if scores else 0
                demisto.results(f"### DEBUG: Final URL+Domain score = {int(avg_score)}")
        except Exception as e:
            demisto.results(f"### DEBUG: Domain extraction error: {str(e)}")

        return {
            'value': url,
            'type': 'URL',
            'score': int(avg_score),
            'verdict': self._get_verdict(avg_score),
            'sources': sources if sources else ['No integrations available']
        }

    def _enrich_domain(self, domain: str) -> Dict[str, Any]:
        scores = []
        sources = []

        # Extract root domain from subdomain (sub.example.com -> example.com)
        root_domain = self._extract_root_domain(domain)
        demisto.results(f"### DEBUG: Enriching Domain {domain} (root: {root_domain})")

        # Call domain command -> ALL integrations (VT, OTX, etc.)
        try:
            domain_results = demisto.executeCommand("domain", {"domain": root_domain})
            if domain_results and isinstance(domain_results, list):
                demisto.results(f"### DEBUG: Got {len(domain_results)} results from domain command")

                for result in domain_results:
                    brand = result.get('Brand', 'Unknown')

                    # OTX disabled - timeout
                    # if 'AlienVault' in brand or 'OTX' in brand:
                    #     demisto.results(f"### DEBUG: SKIPPED {brand} for Domain - timeout")
                    #     continue

                    if result.get('Type') == 4:  # Skip errors
                        error_msg = result.get('Contents', 'Unknown error')
                        demisto.results(f"### DEBUG: SKIPPED {brand} for Domain - Error: {error_msg}")
                        continue

                    demisto.results(f"### DEBUG: Processing Domain result from {brand}")
                    score = self._parse_vt_domain(result)  # DBotScore
                    demisto.results(f"### DEBUG: {brand} Domain score = {score}")
                    if score > 0:
                        scores.append(score)
                        sources.append(brand)
        except Exception as e:
            demisto.results(f"### DEBUG: Domain enrichment error: {str(e)}")

        avg_score = sum(scores) / len(scores) if scores else 0

        return {
            'value': domain,
            'type': 'Domain',
            'score': int(avg_score),
            'verdict': self._get_verdict(avg_score),
            'sources': sources if sources else ['No integrations available']
        }

    def _extract_root_domain(self, domain: str) -> str:
        # Extract root domain: sub.example.com -> example.com
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])  # Last 2 parts
        return domain

    def _enrich_file(self, file_hash: str) -> Dict[str, Any]:
        scores = []
        sources = []
        demisto.results(f"### DEBUG: Enriching File {file_hash}")

        # Call file command -> ALL integrations (VT, etc.)
        try:
            file_results = demisto.executeCommand("file", {"file": file_hash})
            if file_results and isinstance(file_results, list):
                demisto.results(f"### DEBUG: Got {len(file_results)} results from file command")

                for result in file_results:
                    brand = result.get('Brand', 'Unknown')

                    if result.get('Type') == 4:  # Skip errors
                        error_msg = result.get('Contents', 'Unknown error')
                        demisto.results(f"### DEBUG: SKIPPED {brand} - Error: {error_msg}")
                        continue

                    demisto.results(f"### DEBUG: Processing File result from {brand}")
                    score = self._parse_vt_file(result)  # DBotScore
                    demisto.results(f"### DEBUG: {brand} File score = {score}")
                    if score > 0:
                        scores.append(score)
                        sources.append(brand)
        except Exception as e:
            demisto.results(f"### DEBUG: File enrichment error: {str(e)}")

        avg_score = sum(scores) / len(scores) if scores else 0
        demisto.results(f"### DEBUG: Final score for {file_hash[:16]}... = {int(avg_score)} from {len(sources)} sources")

        return {
            'value': file_hash,
            'type': 'File',
            'score': int(avg_score),
            'verdict': self._get_verdict(avg_score),
            'sources': sources if sources else ['No integrations available']
        }

    # Parse integrations (all use DBotScore standard)
    def _parse_vt_ip(self, data: Dict[str, Any]) -> int:
        # Extract DBotScore from result (0-3 scale -> 0-100)
        try:
            contents = data.get('Contents', {})
            if isinstance(contents, dict):
                dbot_score = contents.get('DBotScore', {})
                if isinstance(dbot_score, dict):
                    score = dbot_score.get('Score', 0)
                elif isinstance(dbot_score, list) and len(dbot_score) > 0:
                    score = dbot_score[0].get('Score', 0)
                else:
                    return 0

                # Convert XSOAR scale (0-3) to percentage (0-100)
                # 0=Unknown, 1=Good, 2=Suspicious, 3=Bad
                return int(score * 30)
        except:
            pass
        return 0

    def _parse_vt_url(self, data: Dict[str, Any]) -> int:
        return self._parse_vt_ip(data)  # Same structure

    def _parse_vt_domain(self, data: Dict[str, Any]) -> int:
        return self._parse_vt_ip(data)  # Same structure

    def _parse_vt_file(self, data: Dict[str, Any]) -> int:
        return self._parse_vt_ip(data)  # Same structure

    def _parse_abuseipdb(self, data: Dict[str, Any]) -> int:
        return self._parse_vt_ip(data)  # Same structure

    def _parse_gsb(self, data: Dict[str, Any]) -> int:
        return self._parse_vt_ip(data)  # Same structure

    def _get_verdict(self, score: float) -> str:
        # Convert score to verdict (SOC-ready thresholds)
        if score >= 60:
            return 'MALICIOUS'
        elif score >= 30:
            return 'SUSPICIOUS'
        elif score > 0:
            return 'CLEAN'
        else:
            return 'UNKNOWN'


# INCIDENT CLASSIFIER -> Determine incident type

class IncidentClassifier:

    def classify(self, enriched: List[Dict[str, Any]]) -> Dict[str, str]:
        # Determine overall verdict
        verdicts = [x['verdict'] for x in enriched]

        if 'MALICIOUS' in verdicts:
            overall_verdict = 'MALICIOUS'
        elif 'SUSPICIOUS' in verdicts:
            overall_verdict = 'SUSPICIOUS'
        elif 'CLEAN' in verdicts:
            overall_verdict = 'CLEAN'
        else:
            overall_verdict = 'UNKNOWN'

        # Classify incident type based on IOC types
        ioc_types = [x['type'] for x in enriched]

        if 'File' in ioc_types:
            incident_type = 'Malware'
        elif 'URL' in ioc_types:
            incident_type = 'Phishing'
        elif 'IP' in ioc_types:
            incident_type = 'C2 Communication'
        elif 'Domain' in ioc_types:
            incident_type = 'Phishing'
        else:
            incident_type = 'Security Alert'

        return {
            'verdict': overall_verdict,
            'incident_type': incident_type
        }


# MAIN FRAMEWORK -> Orchestrate enrichment workflow

class IncidentEnrichmentFramework:

    def __init__(self):
        self.inc = demisto.incident()
        self.enricher = IOCEnricher()
        self.classifier = IncidentClassifier()

    def run(self) -> str:
        demisto.results("### DEBUG: Framework started")

        # Step 1: Get indicators using appropriate parser
        demisto.results("### DEBUG: Getting indicators...")
        indicators = self._get_indicators()
        demisto.results(f"### DEBUG: Found {len(indicators)} indicators")

        if not indicators:
            return self._format_no_iocs()

        # Step 2: Enrich IOCs with threat intel
        demisto.results(f"### DEBUG: Starting enrichment of {len(indicators)} IOCs...")
        enriched = self.enricher.enrich(indicators)
        demisto.results("### DEBUG: Enrichment complete")

        # Step 3: Classify incident type
        classification = self.classifier.classify(enriched)

        # Step 4: Format markdown report
        report = self._format_report(enriched, classification)

        # Step 5: Set context for playbook
        self._set_context(enriched, classification)

        return report

    def _get_indicators(self) -> List[Dict[str, Any]]:
        # Auto-detect SIEM source and select parser
        custom_fields = self.inc.get('CustomFields', {})

        if 'microsoftsentinelentities' in custom_fields:
            # Sentinel incident detected
            demisto.results("### DEBUG: Detected Sentinel incident - using SentinelParser")
            parser = SentinelParser(self.inc)
        else:
            # Generic/Splunk incident
            demisto.results("### DEBUG: Generic incident - using SplunkParser (searchIndicators)")
            parser = SplunkParser(self.inc)

        # Parse using selected parser
        indicators = parser.parse()

        return indicators

    def _format_report(self, enriched: List[Dict[str, Any]], classification: Dict[str, str]) -> str:
        # Count verdicts
        mal_count = sum(1 for x in enriched if x['verdict'] == 'MALICIOUS')
        susp_count = sum(1 for x in enriched if x['verdict'] == 'SUSPICIOUS')
        clean_count = sum(1 for x in enriched if x['verdict'] == 'CLEAN')

        report = f"""# Incident Enrichment Report

**Overall Verdict:** {classification['verdict']}
**Incident Type:** {classification['incident_type']}

## Statistics
- Total IOCs: {len(enriched)}
- Malicious: {mal_count}
- Suspicious: {susp_count}
- Clean: {clean_count}

## Enrichment Results
"""

        for ioc in enriched:
            symbol = '[!]' if ioc['verdict'] == 'MALICIOUS' else '[?]' if ioc['verdict'] == 'SUSPICIOUS' else '[OK]'

            report += f"""
### {symbol} {ioc['value']} ({ioc['type']})
**Verdict:** {ioc['verdict']} (Score: {ioc['score']}/100)
**Sources:** {', '.join(ioc['sources']) if ioc['sources'] else 'None'}
"""

        return report

    def _format_no_iocs(self) -> str:
        return """# Incident Enrichment Report

**Status:** No IOCs found in this incident

"""

    def _set_context(self, enriched: List[Dict[str, Any]], classification: Dict[str, str]):
        # Set XSOAR context for playbook use
        mal_count = sum(1 for x in enriched if x['verdict'] == 'MALICIOUS')
        susp_count = sum(1 for x in enriched if x['verdict'] == 'SUSPICIOUS')
        clean_count = sum(1 for x in enriched if x['verdict'] == 'CLEAN')

        demisto.results({
            'Type': 1,  # Entry type
            'ContentsFormat': 'json',
            'Contents': {},
            'EntryContext': {
                'IncidentEnrichment': {
                    'OverallVerdict': classification['verdict'],
                    'IncidentType': classification['incident_type'],
                    'IOCCount': len(enriched),
                    'MaliciousCount': mal_count,
                    'SuspiciousCount': susp_count,
                    'CleanCount': clean_count
                }
            }
        })


# Entry point
def main():
    try:
        framework = IncidentEnrichmentFramework()
        report = framework.run()
        demisto.results(report)
    except Exception as e:
        demisto.results(f"Error: {str(e)}")


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
