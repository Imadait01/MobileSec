print('=== SCANS ===');
const scan = db.scans.findOne({}, { sort: { _id: -1 } });
print(JSON.stringify(scan, null, 2));

print('=== APK ===');
const apk = db.apk_results.findOne({}, { sort: { _id: -1 } });
print(JSON.stringify(apk, null, 2));

print('=== NET ===');
const net = db.network_results.findOne({}, { sort: { _id: -1 } });
print(JSON.stringify(net, null, 2));
