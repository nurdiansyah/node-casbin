import fs from 'fs';
// readFile return a promise for readFile.
export function readFile(path: string, encoding?: BufferEncoding): any {
  return new Promise((resolve, reject) => {
    fs.readFile(path, encoding || 'utf8', (error, data) => {
      if (error) {
        reject(error);
      }
      resolve(data);
    });
  });
}

// writeFile return a promise for writeFile.
export function writeFile(path: string, file: string, encoding: BufferEncoding | null = null): any {
  return new Promise((resolve, reject) => {
    fs.writeFile(path, file, encoding || 'utf8', (error) => {
      if (error) {
        reject(error);
      }
      resolve(true);
    });
  });
}
