/* eslint-disable @typescript-eslint/no-floating-promises -- node:test's describe/it return promises that the runner already tracks */
import { expect } from 'chai';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';
import { createVerify, generateKeyPairSync } from 'node:crypto';
import type { WebResourceType as WebResource } from '@balena/sbvr-types';
import {
	CloudFrontHandler,
	type CloudFrontHandlerProps,
} from '../lib/index.ts';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
	modulusLength: 2048,
	privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
	publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const config: CloudFrontHandlerProps = {
	region: 'us-east-1',
	accessKey: 'test-access-key',
	secretKey: 'test-secret-key',
	endpoint: 'https://s3.test.com',
	bucket: 'test-bucket',
	cfPublicKeyId: 'K2TESTKEYPAIRID',
	cfSecretKey: privateKey,
	cfDistributionDomain: 'https://cdn.test.com',
};

// The href S3Handler stores for an uploaded file
const s3Href = (fileKey: string) =>
	`${config.endpoint}/${config.bucket}/${fileKey}`;

const signHref = async (handler: CloudFrontHandler, href: string) => {
	const webResource = await handler.onPreRespond({
		filename: 'file.txt',
		href,
	});
	return webResource.href;
};

// Rebuilds the canned policy of a CloudFront signed URL and verifies its signature
const parseCloudFrontUrl = (signedUrl: string) => {
	const url = new URL(signedUrl);
	const expires = Number(url.searchParams.get('Expires'));
	const keyPairId = url.searchParams.get('Key-Pair-Id');
	const signature = (url.searchParams.get('Signature') ?? '')
		.replace(/-/g, '+')
		.replace(/_/g, '=')
		.replace(/~/g, '/');
	url.search = '';
	const resource = url.toString();
	const policy = JSON.stringify({
		Statement: [
			{
				Resource: resource,
				Condition: { DateLessThan: { 'AWS:EpochTime': expires } },
			},
		],
	});
	const signatureIsValid = createVerify('RSA-SHA1')
		.update(policy)
		.verify(publicKey, signature, 'base64');
	return { resource, expires, keyPairId, signatureIsValid };
};

// memoizee starts the maxAge timer of a promise result on a later tick
const flush = () => new Promise((resolve) => setImmediate(resolve));

const now = new Date('2026-01-01T00:00:00.000Z').getTime();

describe('CloudFrontHandler', function () {
	afterEach(() => {
		mock.timers.reset();
		mock.restoreAll();
	});

	describe('onPreRespond', function () {
		it('should replace the S3 href with a signed CloudFront URL', async function () {
			const handler = new CloudFrontHandler(config);
			const signedUrl = await signHref(handler, s3Href('logo_image_1'));

			const { resource, keyPairId, signatureIsValid } =
				parseCloudFrontUrl(signedUrl);
			expect(resource).to.equal(
				'https://cdn.test.com/test-bucket/logo_image_1',
			);
			expect(keyPairId).to.equal('K2TESTKEYPAIRID');
			expect(signatureIsValid).to.be.true;
		});

		it('should expire the URL signedUrlExpireTimeSeconds from now', async function () {
			mock.timers.enable({ apis: ['Date'], now });
			const handler = new CloudFrontHandler({
				...config,
				signedUrlExpireTimeSeconds: 3600,
				signedUrlCacheExpireTimeSeconds: 1800,
			});
			const signedUrl = await signHref(handler, s3Href('logo_image_1'));

			expect(parseCloudFrontUrl(signedUrl).expires).to.equal(now / 1000 + 3600);
		});

		it('should ignore query parameters on the stored href', async function () {
			const handler = new CloudFrontHandler(config);
			const signedUrl = await signHref(
				handler,
				`${s3Href('logo_image_1')}?X-Amz-Signature=stale`,
			);

			const { resource, signatureIsValid } = parseCloudFrontUrl(signedUrl);
			expect(resource).to.equal(
				'https://cdn.test.com/test-bucket/logo_image_1',
			);
			expect(signatureIsValid).to.be.true;
		});

		it('should keep the other webresource fields', async function () {
			const handler = new CloudFrontHandler(config);
			const webResource: WebResource = {
				filename: 'file.txt',
				href: s3Href('logo_image_1'),
				content_type: 'text/plain',
				size: 42,
			};
			const result = await handler.onPreRespond(webResource);

			expect(result).to.include({
				filename: 'file.txt',
				content_type: 'text/plain',
				size: 42,
			});
			expect(result.href).to.match(/^https:\/\/cdn\.test\.com\//);
		});

		it('should leave a webresource without an href untouched', async function () {
			const handler = new CloudFrontHandler(config);
			const webResource = { filename: 'file.txt' } as WebResource;
			const result = await handler.onPreRespond(webResource);

			expect(result).to.deep.equal({ filename: 'file.txt' });
		});

		it('should fall back to an S3 signed URL when CloudFront signing fails', async function () {
			const consoleError = mock.method(console, 'error', () => {
				// silence the expected error logs
			});
			const handler = new CloudFrontHandler(config);
			// Simulate a signing failure at runtime
			Object.assign(handler, { cfSecretKey: 'invalid-key' });
			const signedUrl = new URL(
				await signHref(handler, s3Href('logo_image_1')),
			);

			expect(signedUrl.origin).to.equal('https://s3.test.com');
			expect(signedUrl.pathname).to.equal('/test-bucket/logo_image_1');
			expect(signedUrl.searchParams.get('X-Amz-Signature')).to.be.a('string');
			expect(signedUrl.searchParams.get('X-Amz-Expires')).to.equal('86400');
			expect(consoleError.mock.callCount()).to.be.greaterThan(0);
		});
	});

	describe('signed URL cache', function () {
		beforeEach(() => {
			mock.timers.enable({ apis: ['Date', 'setTimeout'], now });
		});

		it('should reuse the signed URL within signedUrlCacheExpireTimeSeconds', async function () {
			const handler = new CloudFrontHandler({
				...config,
				signedUrlExpireTimeSeconds: 100,
				signedUrlCacheExpireTimeSeconds: 60,
			});
			const firstUrl = await signHref(handler, s3Href('logo_image_1'));
			await flush();
			mock.timers.tick(59_000);

			expect(await signHref(handler, s3Href('logo_image_1'))).to.equal(
				firstUrl,
			);
		});

		it('should sign a new URL once signedUrlCacheExpireTimeSeconds has passed', async function () {
			const handler = new CloudFrontHandler({
				...config,
				signedUrlExpireTimeSeconds: 100,
				signedUrlCacheExpireTimeSeconds: 60,
			});
			const firstUrl = await signHref(handler, s3Href('logo_image_1'));
			await flush();
			mock.timers.tick(61_000);
			const secondUrl = await signHref(handler, s3Href('logo_image_1'));

			expect(secondUrl).to.not.equal(firstUrl);
			expect(parseCloudFrontUrl(secondUrl).expires).to.equal(
				now / 1000 + 61 + 100,
			);
		});

		it('should cache URLs per file', async function () {
			const handler = new CloudFrontHandler(config);
			const firstUrl = await signHref(handler, s3Href('logo_image_1'));
			const secondUrl = await signHref(handler, s3Href('logo_image_2'));

			expect(parseCloudFrontUrl(firstUrl).resource).to.equal(
				'https://cdn.test.com/test-bucket/logo_image_1',
			);
			expect(parseCloudFrontUrl(secondUrl).resource).to.equal(
				'https://cdn.test.com/test-bucket/logo_image_2',
			);
		});
	});
});
