import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/database/local-adapter';
import { localStorageAdapter } from '@/lib/storage/local-adapter';

export async function POST(request: NextRequest) {
  try {
    const { action, userId, fileId } = await request.json();

    switch (action) {
      case 'validate-owner': {
        const metadata = await localStorageAdapter.getMetadata(fileId);
        if (!metadata) {
          return NextResponse.json({ authorized: false }, { status: 404 });
        }
        return NextResponse.json({ authorized: metadata.userId === userId });
      }
      case 'store-file': {
        return NextResponse.json({ success: true });
      }
      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
  } catch (error) {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }
}
