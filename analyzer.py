import pyshark
import tempfile
import os

def extract_sessions(uploaded_file):
    # Save uploaded PCAP file to temp location
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name
    
    cap = pyshark.FileCapture(tmp_path, use_json=True, include_raw=False)
    sessions = []
    seen_dns_queries = set()  # Track unique DNS queries to avoid duplicates
    seen_dns_responses = set()  # Track unique DNS responses
    
    print("\n" + "="*80)
    print(f"{'TYPE':<10} | {'DOMAIN/RESULT':<50} | {'IP':<15}")
    print("="*80)
    
    try:
        for i, pkt in enumerate(cap):
            # For larger frames you might want to uncomment these and add limits
            #if i >= 35000:
             #   break
            
            packet_info = {
                "No": i + 1,
                "Timestamp": pkt.sniff_time.isoformat(),
                "Protocol": pkt.highest_layer,
                "Length": pkt.length,
                "Info": pkt._packet_string,
            }
            
            # IP addresses
            if hasattr(pkt, 'ip'):
                packet_info["Src IP"] = pkt.ip.src
                packet_info["Dst IP"] = pkt.ip.dst
            
            # TCP or UDP ports
            if hasattr(pkt, 'tcp'):
                packet_info["Src Port"] = pkt.tcp.srcport
                packet_info["Dst Port"] = pkt.tcp.dstport
            elif hasattr(pkt, 'udp'):
                packet_info["Src Port"] = pkt.udp.srcport
                packet_info["Dst Port"] = pkt.udp.dstport
            
            # DNS handling - capture ALL DNS packets, but track unique domains
            if hasattr(pkt, 'dns'):
                dns_found = True
                
                # Debug: Show what DNS attributes are available (only for first few DNS packets)
                if len(seen_dns_queries) < 5:
                    print(f"[DEBUG] DNS packet {i+1} attributes: {list(pkt.dns._all_fields.keys())}")
                
                # Try different ways to get DNS query name
                domain = None
                if hasattr(pkt.dns, 'qry_name'):
                    domain = pkt.dns.qry_name
                elif hasattr(pkt.dns, 'query_name'):
                    domain = pkt.dns.query_name
                elif 'dns.qry.name' in pkt.dns._all_fields:
                    domain = pkt.dns._all_fields['dns.qry.name']
                elif 'Queries' in pkt.dns._all_fields:
                    # Handle complex DNS structure
                    queries = pkt.dns._all_fields['Queries']
                    if isinstance(queries, dict):
                        for query_key in queries.keys():
                            if 'dns.qry.name' in queries[query_key]:
                                domain = queries[query_key]['dns.qry.name']
                                break
                            # Sometimes the domain is in the key itself
                            if ':' in query_key:
                                domain = query_key.split(':')[0].strip()
                                break
                
                if domain:
                    packet_info["DNS Query"] = domain
                    packet_info["DNS Query Type"] = getattr(pkt.dns, 'qry_type', '')
                    
                    if domain not in seen_dns_queries:
                        seen_dns_queries.add(domain)
                        packet_info["DNS Query First Time"] = True
                        print(f"{'QUERY':<10} | {domain}")
                    else:
                        packet_info["DNS Query First Time"] = False
                
                # Try different ways to get DNS response/answer
                resolved_ip = None
                response_domain = None
                
                # Check if this is a DNS response (not just a query)
                if hasattr(pkt.dns, 'flags_tree') and pkt.dns.flags_tree.get('dns.flags.response') == '1':
                    # This is a DNS response packet
                    
                    # Try to get domain and IP from Answers structure
                    if 'Answers' in pkt.dns._all_fields:
                        answers = pkt.dns._all_fields['Answers']
                        if isinstance(answers, dict):
                            for answer_key, answer_data in answers.items():
                                if isinstance(answer_data, dict):
                                    # Extract domain name (before the colon in key)
                                    if ':' in answer_key:
                                        response_domain = answer_key.split(':')[0].strip()
                                    
                                    # Extract IP address
                                    if 'dns.a' in answer_data:
                                        resolved_ip = answer_data['dns.a']
                                        break
                                    elif 'dns.resp.addr' in answer_data:
                                        resolved_ip = answer_data['dns.resp.addr']
                                        break
                    
                    # Fallback: try direct attributes
                    if not resolved_ip:
                        if hasattr(pkt.dns, 'a'):
                            resolved_ip = pkt.dns.a
                        elif 'dns.a' in pkt.dns._all_fields:
                            resolved_ip = pkt.dns._all_fields['dns.a']
                    
                    # Get domain from query if not found in answer
                    if not response_domain and domain:
                        response_domain = domain
                    elif not response_domain and hasattr(pkt.dns, 'resp_name'):
                        response_domain = pkt.dns.resp_name
                    
                    if resolved_ip and response_domain:
                        response_pair = f"{response_domain} → {resolved_ip}"
                        packet_info["DNS Response"] = response_pair
                        
                        if response_pair not in seen_dns_responses:
                            seen_dns_responses.add(response_pair)
                            packet_info["DNS Response First Time"] = True
                            print(f"{'RESPONSE':<10} | {response_domain:<50} → {resolved_ip}")
                            
                    # Debug: Show response packet structure for first few
                    elif len(seen_dns_responses) < 3:
                        print(f"[DEBUG] DNS Response packet {i+1} structure:")
                        if 'Answers' in pkt.dns._all_fields:
                            print(f"[DEBUG] Answers: {pkt.dns._all_fields['Answers']}")
                        else:
                            print(f"[DEBUG] No Answers field, available: {list(pkt.dns._all_fields.keys())}")
                
                else:
                    # This is a query packet
                    pass
            
            # HTTP Host and URI
            if hasattr(pkt, 'http'):
                packet_info["HTTP Host"] = getattr(pkt.http, 'host', '')
                packet_info["HTTP URI"] = getattr(pkt.http, 'request_uri', '')
            
            # TLS Server Name Indication (SNI)
            if hasattr(pkt, 'ssl'):
                try:
                    packet_info["TLS SNI"] = pkt.ssl.handshake_extensions_server_name
                except AttributeError:
                    pass
            
            # Mark malformed LDAP packets
            if hasattr(pkt, 'ldap'):
                if 'malformed' in pkt.ldap._all_fields:
                    packet_info["LDAP Malformed"] = True
            
            sessions.append(packet_info)
    
    except Exception as e:
        sessions.append({"Error": str(e)})
    finally:
        cap.close()
        os.remove(tmp_path)
    
    print("="*80)
    print(f"{'SUMMARY':<10} | Unique DNS queries: {len(seen_dns_queries)}")
    print(f"{'SUMMARY':<10} | Unique DNS responses: {len(seen_dns_responses)}")
    print(f"{'SUMMARY':<10} | Total sessions extracted: {len(sessions)}")
    print("="*80)
    
    return sessions
