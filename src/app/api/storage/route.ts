import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// El stub anterior usaba IndexedDB en el servidor (no existe en App Service).
// Usa /api/storage/upload, /api/storage/download, /api/storage/delete y /api/files.
export async function GET() {
  return NextResponse.json({
    error: 'Ruta desactivada. Usa /api/storage/upload, /api/storage/download o /api/storage/delete.',
  }, { status: 410 });
}

export async function POST(_request: NextRequest) {
  return NextResponse.json(
    { error: 'Ruta desactivada. Usa /api/storage/upload, /api/storage/download o /api/storage/delete.' },
    { status: 410 }
  );
}
