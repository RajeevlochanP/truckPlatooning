const fs = require('fs');
const path = require('path');

const pathLengths = [10, 20, 30, 40, 50];
const csvPath = path.join(__dirname, 'benchmark_communication.csv');

// Constants per waypoint (in Bytes)
const HE_PSI_BYTES_PER_WAYPOINT = 6217;
const TAROT_BYTES_PER_WAYPOINT = 8192;

const csvHeader = "PathLength(l),HE_PSI_KB,TAROT_KB";
let csvContent = csvHeader + "\n";
console.log(csvHeader);

for (const l of pathLengths) {
    const hePsiKb = (HE_PSI_BYTES_PER_WAYPOINT * l / 1024).toFixed(2);
    const tarotKb = (TAROT_BYTES_PER_WAYPOINT * l / 1024).toFixed(2);
    
    const row = `${l},${hePsiKb},${tarotKb}`;
    console.log(row);
    csvContent += row + "\n";
}

fs.writeFileSync(csvPath, csvContent, 'utf8');
console.log(`\nCommunication benchmarks completed. Results saved to benchmark_communication.csv`);
