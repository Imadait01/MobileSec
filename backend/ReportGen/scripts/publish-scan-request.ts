import { Kafka } from 'kafkajs';
import { v4 as uuidv4 } from 'uuid';

async function main() {
  const brokers = (process.env.KAFKA_BROKERS || 'localhost:9092').split(',');
  const kafka = new Kafka({ clientId: 'reportgen-publisher', brokers });
  const producer = kafka.producer();
  await producer.connect();

  const scanId = process.argv[2] || `scan-${uuidv4()}`;
  const payload = { id: scanId, timestamp: new Date().toISOString() };

  await producer.send({ topic: process.env.KAFKA_TOPIC_SCAN_REQUESTS || 'scan-requests', messages: [{ key: scanId, value: JSON.stringify(payload) }] });
  console.log('Published scan request', payload);
  await producer.disconnect();
}

main().catch((e) => { console.error('Failed to publish', e); process.exit(1); });