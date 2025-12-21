
import asyncio
import json
import logging
import functools
from concurrent.futures import ThreadPoolExecutor
from confluent_kafka import Consumer
from config import settings
from services import get_mongodb_client, get_nova_client

logger = logging.getLogger(__name__)

async def start_consumer():
    """Starts the Kafka Consumer loop in background"""
    asyncio.create_task(consume_loop())

async def consume_loop():
    # Wait for service startup
    await asyncio.sleep(10)
    
    logger.info(f"Starting FixSuggest Kafka Consumer group=fixsuggest-group brokers={settings.kafka_brokers}")
    
    conf = {
        'bootstrap.servers': settings.kafka_brokers,
        'group.id': 'fixsuggest-group',
        'auto.offset.reset': 'earliest'
    }
    
    try:
        # We'll run it directly, usually fast.
        print("FixSuggest: Creating Consumer...", flush=True)
        consumer = Consumer(conf)
        print("FixSuggest: Subscribing...", flush=True)
        consumer.subscribe(['scan-requests'])
        print("FixSuggest: Subscribed to scan-requests", flush=True)
        logger.info("Subscribed to scan-requests")
    except Exception as e:
        logger.error(f"Failed to create consumer: {e}")
        return

    while True:
        try:
            # Poll(0) is non-blocking
            msg = consumer.poll(0)
            
            if msg is None:
                await asyncio.sleep(1)
                continue
                
            if msg.error():
                print(f"FixSuggest Kafka error: {msg.error()}", flush=True)
                logger.error(f"Kafka error: {msg.error()}")
                continue
            
            value = msg.value().decode('utf-8')
            print(f"FixSuggest Received message: {value}", flush=True)
            logger.info(f"Received message: {value}")
            
            try:
                data = json.loads(value)
                scan_id = data.get('id')
                if scan_id:
                     await process_scan(scan_id)
            except Exception as e:
                logger.error(f"Error processing message: {e}")
                
        except Exception as e:
            logger.error(f"Consumer loop error: {e}")
            await asyncio.sleep(5)
    
    # Unreachable but good practice
    consumer.close()

async def process_scan(scan_id: str):
    logger.info(f"Processing scan {scan_id}")
    mongo_client = get_mongodb_client()
    nova_client = get_nova_client()
    loop = asyncio.get_running_loop()
    
    # Wait for results
    for attempt in range(12): # 2 minutes
        # Sync call in executor
        vuln_data = await loop.run_in_executor(None, mongo_client.get_all_vulnerabilities, scan_id)
        scan_info = await loop.run_in_executor(None, mongo_client.get_scan_info, scan_id)
        
        tools = vuln_data.get('by_tool', {})
        total = vuln_data.get('total', 0)
        
        ready = False
        if scan_info:
            stages = scan_info.get('stages', {})
            # Check completion
            if (stages.get('apk_scanner') == 'completed' and 
                stages.get('network_inspector') == 'completed' and
                stages.get('secret_hunter') == 'completed' and 
                stages.get('crypto_check') == 'completed'):
                ready = True
        
        # If ready or timeout almost reached (attempt > 10) or we have data and wait reasonable time
        if ready or (attempt > 6 and total > 0): 
             logger.info(f"Generating suggestions for {scan_id} (Total vulns: {total})")
             
             suggestions = []
             vulnerabilities = vuln_data.get("vulnerabilities", [])
             
             # Enrich sequentially (could be parallel but API limits?)
             for vuln in vulnerabilities:
                 try:
                     # generate_natural_suggestion_async IS async
                     sug = await nova_client.generate_natural_suggestion_async(vuln)
                     suggestions.append(sug)
                 except Exception as e:
                     logger.error(f"Gen error: {e}")
                     # Fallback
                     # Accessing private method _generate_natural_fallback ?
                     # Should expose public fallback or just skip
                     pass
             
             # Save sync in executor
             model = nova_client.model if nova_client.is_configured else "fallback"
             await loop.run_in_executor(None, mongo_client.save_suggestions, scan_id, suggestions, model)
             
             logger.info(f"Saved {len(suggestions)} suggestions for {scan_id}")
             # Update stage
             # mongo_client.update_scan_status(scan_id, 'fixsuggest', 'completed') # If method exists
             return

        logger.info(f"Waiting for scan results {scan_id} (Attempt {attempt+1}/12)...")
        await asyncio.sleep(10)
        
    logger.warning(f"Timeout waiting for results for {scan_id}")
