const fs = require('fs').promises;
const path = require('path');

async function generateManifest() {
  const publicDir = path.join(__dirname, 'public');
  const manifestPath = path.join(publicDir, 'manifest.json');

  // Read existing manifest
  let manifest;
  try {
    const manifestData = await fs.readFile(manifestPath, 'utf8');
    manifest = JSON.parse(manifestData);
  } catch (error) {
    console.error('Error reading manifest.json:', error);
    return;
  }

  // Get all HTML files
  const files = await fs.readdir(publicDir);
  const htmlFiles = files.filter(file => file.endsWith('.html'));

  const panels = [];

  for (const file of htmlFiles) {
    const filePath = path.join(publicDir, file);

    try {
      const content = await fs.readFile(filePath, 'utf8');

      // Extract title
      const titleMatch = content.match(/<title>(.*?)<\/title>/i);
      const title = titleMatch ? titleMatch[1].trim() : file.replace('.html', '').replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

      // Extract description from meta or first h1/p
      let description = '';
      const metaDescMatch = content.match(/<meta name="description" content="(.*?)"/i);
      if (metaDescMatch) {
        description = metaDescMatch[1];
      } else {
        const h1Match = content.match(/<h1[^>]*>(.*?)<\/h1>/i);
        if (h1Match) {
          description = h1Match[1].replace(/<[^>]*>/g, '').trim();
        }
      }

      if (!description) {
        description = `${title} interface`;
      }

      panels.push({
        name: title,
        file: file,
        description: description
      });

    } catch (error) {
      console.error(`Error processing ${file}:`, error);
    }
  }

  // Sort panels by name
  panels.sort((a, b) => a.name.localeCompare(b.name));

  // Update manifest
  manifest.panels = panels;

  // Write back
  await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
  console.log('Manifest updated with all HTML files');
}

generateManifest().catch(console.error);