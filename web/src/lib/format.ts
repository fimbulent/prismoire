import { formatDistanceToNowStrict } from 'date-fns';

export function relativeTime(dateStr: string): string {
	return formatDistanceToNowStrict(new Date(dateStr), { addSuffix: true });
}
