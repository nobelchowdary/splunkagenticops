"""Investigation Agent — Autonomous deep-dive investigation via SPL queries.

Key design decisions addressing SPL hallucination:
1. Schema Discovery — Agent receives verified index/field names before generating SPL
2. Self-Correction Loop — On SPL errors or zero results, agent rewrites and retries (up to 3x)
3. Transparency — Every step exposes raw SPL, raw results, and reasoning to the UI
"""

import json
from typing import Dict, Any, Callable, Optional, List
from datetime import datetime

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_anthropic import ChatAnthropic

from tools.splunk_mcp import get_mcp_client
from tools.schema_discovery import get_schema_discovery
from models import Finding, Severity, TimelineEvent
from config import get_settings


# MITRE ATT&CK mapping for common SPL patterns
MITRE_PATTERNS = {
    "failed login": ("T1110", "Credential Access", "Brute Force"),
    "successful login after failure": ("T1078", "Defense Evasion", "Valid Accounts"),
    "lateral movement": ("T1021", "Lateral Movement", "Remote Services"),
    "data transfer": ("T1048", "Exfiltration", "Exfiltration Over Alternative Protocol"),
    "process creation": ("T1059", "Execution", "Command and Scripting Interpreter"),
    "registry modification": ("T1112", "Defense Evasion", "Modify Registry"),
    "scheduled task": ("T1053", "Persistence", "Scheduled Task/Job"),
    "dns query unusual": ("T1071", "Command and Control", "Application Layer Protocol"),
}

# Max retries for self-correction on SPL errors
MAX_SPL_RETRIES = 3


def build_investigation_prompt(schema_context: str) -> str:
    """Build the system prompt with injected schema context."""
    return f"""You are a Security Operations Center (SOC) investigation agent integrated with Splunk.
Your job is to investigate security incidents by generating and analyzing SPL (Search Processing Language) queries.

{schema_context}

### CRITICAL SPL RULES:
1. ALWAYS start queries with: search index=<index_name>
2. NEVER use index names or field names not listed in the schema above
3. Use | (pipe) for chaining commands: search index=auth | stats count by user
4. For time filtering, use earliest= and latest= in the search: search index=auth earliest=-24h
5. Common commands: stats, timechart, table, where, eval, rex, join, dedup, sort, head, tail
6. String comparisons are case-sensitive: action="failure" NOT action="Failure"
7. Use wildcards sparingly: src_ip="192.168.*" is OK
8. For multiple values: (src_ip="1.2.3.4" OR src_ip="5.6.7.8")

### Investigation Strategy:
1. Start broad, then narrow down based on findings
2. Correlate across multiple indexes (auth + network + endpoint + dns)
3. Look for temporal patterns (what happened before/after the alert)
4. Identify lateral movement, privilege escalation, and data exfiltration
5. Map findings to MITRE ATT&CK techniques
6. After 3-5 queries with strong findings, you can conclude

### Output Format:
For each investigation step, output ONLY valid JSON (no markdown, no explanation outside JSON):
{{
    "spl_query": "search index=auth action=failure | stats count by src_ip, user | where count > 50",
    "purpose": "Find brute force sources with more than 50 failed login attempts",
    "reasoning": "Starting with auth failures because the alert mentions credential access",
    "next_if_found": "Trace the source IP's other activity across network and endpoint indexes",
    "next_if_empty": "Broaden time range or check for different attack patterns"
}}

When you have enough evidence to conclude (typically after 4-8 steps):
{{
    "conclusion": true,
    "summary": "Detailed findings summary with evidence chain",
    "severity": "critical|high|medium|low",
    "mitre_techniques": ["T1110", "T1078", "T1021"],
    "affected_assets": ["WKS-JSMITH-01", "SRV-DC01"],
    "affected_users": ["jsmith"],
    "recommendations": ["Disable compromised account", "Block attacker IP", "Isolate affected hosts"]
}}"""


async def run_investigation(
    triage_result: Dict[str, Any],
    alert_data: Dict[str, Any],
    callback: Optional[Callable] = None,
    max_steps: int = 12,
) -> Dict[str, Any]:
    """
    Run an autonomous investigation using iterative SPL queries.

    Features:
    - Schema-aware: Discovers Splunk environment before generating SPL
    - Self-correcting: Retries failed queries with error context (up to 3x per step)
    - Transparent: Streams raw SPL, raw results, and reasoning to UI
    """
    settings = get_settings()
    mcp = get_mcp_client()
    schema_discovery = get_schema_discovery()
    llm = ChatAnthropic(
        model=settings.llm_model,
        api_key=settings.anthropic_api_key,
        temperature=0.1,
    )

    findings: List[Dict[str, Any]] = []
    timeline_events: List[Dict[str, Any]] = []

    # === PHASE 0: SCHEMA DISCOVERY ===
    if callback:
        await callback({
            "type": "agent_action",
            "agent": "investigation",
            "action": "discovering_schema",
            "detail": "Querying Splunk for available indexes, sourcetypes, and fields...",
        })

    schema = await schema_discovery.discover_schema()
    schema_context = schema_discovery.get_schema_prompt(schema)

    if callback:
        await callback({
            "type": "agent_action",
            "agent": "investigation",
            "action": "schema_loaded",
            "detail": f"Schema loaded: {len(schema.get('indexes', []))} indexes, {len(schema.get('fields_by_sourcetype', {}))} sourcetypes mapped",
            "raw_data": schema,
        })

    # Build context-aware system prompt
    system_prompt = build_investigation_prompt(schema_context)

    # Build initial investigation context
    context = f"""### Investigation Context:
- **Alert**: {alert_data.get('title', 'Unknown')}
- **Description**: {alert_data.get('description', '')}
- **Triage Classification**: {triage_result.get('threat_category', 'Unknown')} (Severity: {triage_result.get('severity', 'medium')})
- **Source IP**: {alert_data.get('source_ip', 'N/A')}
- **Destination IP**: {alert_data.get('dest_ip', 'N/A')}
- **User**: {alert_data.get('user', 'N/A')}
- **IOCs Found**: {', '.join(triage_result.get('iocs', [])) or 'None'}
- **MITRE Techniques (from triage)**: {', '.join(triage_result.get('mitre_techniques', [])) or 'None'}
- **Suggested Investigation Steps**: {json.dumps(triage_result.get('investigation_steps', []))}

Begin your investigation. Generate your first SPL query targeting the most critical evidence."""

    if callback:
        await callback({
            "type": "agent_action",
            "agent": "investigation",
            "action": "starting",
            "detail": f"Beginning autonomous investigation (max {max_steps} steps, self-correction enabled)...",
        })

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=context),
    ]

    for step in range(max_steps):
        # Get next investigation step from LLM
        response = await llm.ainvoke(messages)
        response_text = response.content

        # Parse JSON from response
        try:
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                step_data = json.loads(response_text[json_start:json_end])
            else:
                break
        except json.JSONDecodeError:
            # If LLM didn't output valid JSON, ask it to retry
            messages.append(response)
            messages.append(HumanMessage(content="Your response was not valid JSON. Please output ONLY a JSON object with spl_query, purpose, reasoning fields."))
            continue

        # Check if investigation is concluded
        if step_data.get("conclusion"):
            if callback:
                await callback({
                    "type": "agent_action",
                    "agent": "investigation",
                    "action": "concluded",
                    "detail": step_data.get("summary", "Investigation complete"),
                    "reasoning": step_data.get("summary", ""),
                })

            findings.append(
                Finding(
                    agent="investigation",
                    type="conclusion",
                    title="Investigation Conclusion",
                    description=step_data.get("summary", ""),
                    severity=Severity(step_data.get("severity", "medium")),
                    confidence=0.9,
                ).model_dump()
            )

            return {
                "findings": findings,
                "timeline_events": timeline_events,
                "summary": step_data.get("summary"),
                "mitre_techniques": step_data.get("mitre_techniques", []),
                "affected_assets": step_data.get("affected_assets", []),
                "affected_users": step_data.get("affected_users", []),
                "recommendations": step_data.get("recommendations", []),
                "steps_taken": step + 1,
            }

        # === EXECUTE SPL WITH SELF-CORRECTION LOOP ===
        spl_query = step_data.get("spl_query", "")
        purpose = step_data.get("purpose", "")
        reasoning = step_data.get("reasoning", "")

        if not spl_query:
            break

        # Stream the reasoning to UI for transparency
        if callback:
            await callback({
                "type": "agent_action",
                "agent": "investigation",
                "action": "reasoning",
                "detail": f"Step {step + 1}: {purpose}",
                "reasoning": reasoning,
                "spl_query": spl_query,
            })

        # Self-correction loop: retry SPL on error
        query_result = None
        results_data = []
        final_spl = spl_query
        retry_count = 0

        for attempt in range(MAX_SPL_RETRIES):
            query_result = await mcp.run_custom_spl(final_spl)
            error = query_result.get("error")

            if error:
                retry_count += 1
                if callback:
                    await callback({
                        "type": "agent_action",
                        "agent": "investigation",
                        "action": "spl_error",
                        "detail": f"SPL Error (attempt {attempt + 1}/{MAX_SPL_RETRIES}): {error}",
                        "spl_query": final_spl,
                        "reasoning": f"Query failed. Self-correcting...",
                    })

                if attempt < MAX_SPL_RETRIES - 1:
                    # Ask LLM to fix the query
                    correction_prompt = f"""Your SPL query failed with this error:
ERROR: {error}

Failed query: {final_spl}

Fix the query using ONLY the indexes and fields from the schema. Output ONLY the corrected JSON:
{{
    "spl_query": "corrected query here",
    "purpose": "{purpose}",
    "reasoning": "explanation of what you fixed"
}}"""
                    correction_response = await llm.ainvoke([
                        SystemMessage(content=system_prompt),
                        HumanMessage(content=correction_prompt),
                    ])
                    try:
                        correction_text = correction_response.content
                        cj_start = correction_text.find("{")
                        cj_end = correction_text.rfind("}") + 1
                        if cj_start >= 0 and cj_end > cj_start:
                            correction_data = json.loads(correction_text[cj_start:cj_end])
                            final_spl = correction_data.get("spl_query", final_spl)

                            if callback:
                                await callback({
                                    "type": "agent_action",
                                    "agent": "investigation",
                                    "action": "self_correcting",
                                    "detail": f"Rewritten query (attempt {attempt + 2})",
                                    "spl_query": final_spl,
                                    "reasoning": correction_data.get("reasoning", "Corrected SPL syntax"),
                                })
                    except (json.JSONDecodeError, AttributeError):
                        pass
            else:
                # Success — break out of retry loop
                results_data = query_result.get("results", [])
                break

        result_count = len(results_data)

        # Record timeline event with full transparency
        timeline_events.append(
            TimelineEvent(
                timestamp=datetime.utcnow(),
                agent="investigation",
                action="spl_query",
                detail=f"{purpose} — {result_count} results (retries: {retry_count})",
                spl_query=final_spl,
                result_count=result_count,
            ).model_dump()
        )

        # Build result summary for LLM
        if results_data:
            sample = results_data[:5]
            result_summary = f"Query returned {result_count} results.\nSample (first {min(5, result_count)}):\n{json.dumps(sample, indent=2, default=str)}"
        else:
            result_summary = f"Query returned 0 results."

        # Stream raw results to UI for full transparency
        if callback:
            await callback({
                "type": "agent_action",
                "agent": "investigation",
                "action": "results",
                "detail": f"Step {step + 1} complete: {result_count} results returned",
                "spl_query": final_spl,
                "result_count": result_count,
                "raw_results": results_data[:10] if results_data else [],
                "reasoning": f"{'Self-corrected ' + str(retry_count) + 'x. ' if retry_count else ''}Analyzing results to determine next step.",
            })

        # Check for MITRE patterns in results
        for pattern, (technique_id, tactic, technique_name) in MITRE_PATTERNS.items():
            if pattern in purpose.lower() or pattern in str(results_data).lower():
                findings.append(
                    Finding(
                        agent="investigation",
                        type="correlation",
                        title=f"MITRE ATT&CK: {technique_name}",
                        description=f"Evidence of {technique_name} ({technique_id}) found in step {step + 1}: {purpose}",
                        severity=Severity.HIGH,
                        evidence=final_spl,
                        mitre_technique=technique_id,
                        mitre_tactic=tactic,
                        confidence=0.75,
                    ).model_dump()
                )
                break

        # Feed results back to LLM for next step
        messages.append(response)
        messages.append(HumanMessage(
            content=f"Query results:\n{result_summary}\n\nAnalyze these results and determine your next investigation step. Output ONLY JSON."
        ))

    # If we hit max steps without conclusion
    return {
        "findings": findings,
        "timeline_events": timeline_events,
        "summary": "Investigation reached maximum steps. Manual review recommended.",
        "mitre_techniques": list(set(f.get("mitre_technique") for f in findings if f.get("mitre_technique"))),
        "affected_assets": [],
        "affected_users": [],
        "recommendations": ["Manual review recommended — investigation depth exceeded"],
        "steps_taken": max_steps,
    }


class InvestigationAgent:
    """Wrapper class for follow-up interactive investigations."""

    async def investigate_followup(self, query: str, callback: Optional[Callable] = None, prior_context: Optional[Dict] = None) -> Dict[str, Any]:
        """Run a follow-up investigation query using the same agent logic."""
        settings = get_settings()
        llm = ChatAnthropic(
            model=settings.llm_model,
            api_key=settings.anthropic_api_key,
            max_tokens=4096,
        )
        mcp = get_mcp_client()
        schema_discovery = get_schema_discovery()

        # Discover schema
        schema = await schema_discovery.discover_schema()
        schema_context = schema_discovery.get_schema_prompt(schema)
        if callback:
            await callback({
                "type": "agent_action",
                "agent": "investigation",
                "action": "schema_loaded",
                "detail": "Schema context loaded for follow-up query",
            })

        # Build context from prior investigation results
        prior_summary = ""
        if prior_context:
            prior_summary = f"""
### PRIOR INVESTIGATION RESULTS (use this to answer contextual questions):
- Summary: {prior_context.get('summary', 'N/A')}
- MITRE Techniques Found: {', '.join(prior_context.get('mitre_techniques', []))}
- Affected Assets: {', '.join(prior_context.get('affected_assets', []))}
- Affected Users: {', '.join(prior_context.get('affected_users', []))}
- Recommendations: {', '.join(prior_context.get('recommendations', []))}
- Findings: {json.dumps(prior_context.get('findings', [])[:5], default=str)}
"""

        # Generate SPL from the follow-up question
        system_prompt = build_investigation_prompt(schema_context)
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"""The analyst has a follow-up question about a previous investigation:
{prior_summary}

Analyst's question: "{query}"

If the question can be answered from the prior investigation results above, respond with:
{{"action": "answer", "answer": "<your detailed answer based on prior findings>", "reasoning": "<why>"}}

If the question requires a NEW Splunk query, respond with:
{{"action": "search", "spl": "<your SPL query>", "reasoning": "<why this query>"}}

Output ONLY valid JSON."""),
        ]

        response = await llm.ainvoke(messages)
        response_text = response.content if hasattr(response, 'content') else str(response)

        # Parse and execute
        try:
            # Extract JSON from response
            json_str = response_text
            if "```" in json_str:
                json_str = json_str.split("```")[1].replace("json", "").strip()
            parsed = json.loads(json_str)

            action = parsed.get("action", "search")
            reasoning = parsed.get("reasoning", "")

            # If the LLM can answer from context, no need for a Splunk query
            if action == "answer":
                answer = parsed.get("answer", "")
                if callback:
                    await callback({
                        "type": "agent_action",
                        "agent": "investigation",
                        "action": "results",
                        "detail": answer,
                        "reasoning": reasoning,
                    })
                return {
                    "query": query,
                    "summary": answer,
                    "mitre_techniques": prior_context.get("mitre_techniques", []) if prior_context else [],
                }

            # Otherwise execute the SPL query
            spl_query = parsed.get("spl", "")

            if callback:
                await callback({
                    "type": "agent_action",
                    "agent": "investigation",
                    "action": "querying",
                    "detail": f"Follow-up: {reasoning}",
                    "spl_query": spl_query,
                    "reasoning": reasoning,
                })

            # Execute query
            result = await mcp.search(spl_query)
            results = result.get("results", [])

            if callback:
                await callback({
                    "type": "agent_action",
                    "agent": "investigation",
                    "action": "results",
                    "detail": f"Follow-up query returned {len(results)} results",
                    "result_count": len(results),
                    "raw_results": results[:10],
                })

            return {
                "query": query,
                "spl": spl_query,
                "results": results[:20],
                "summary": f"Follow-up query returned {len(results)} results for: {query}",
            }

        except (json.JSONDecodeError, KeyError) as e:
            if callback:
                await callback({
                    "type": "agent_action",
                    "agent": "investigation",
                    "action": "results",
                    "detail": f"Follow-up processed: {query}",
                })
            return {"query": query, "summary": str(response_text)}
