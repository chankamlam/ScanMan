/*
 * libgd.c —— 取自真实项目的样本
 * 来源：训练数据的【测试集】，模型训练时没见过。
 * 注释里的真实标签用于对比模型预测；注释在函数体外，不进模型输入。
 */


/* ==== 真实标签：有漏洞（CWE-20） ==== */
BGD_DECLARE(gdImagePtr) gdImageCropThreshold(gdImagePtr im, const unsigned int color, const float threshold)
{
	const int width = gdImageSX(im);
	const int height = gdImageSY(im);

	int x,y;
	int match;
	gdRect crop;

	crop.x = 0;
	crop.y = 0;
	crop.width = 0;
	crop.height = 0;

	/* Pierre: crop everything sounds bad */
	if (threshold > 100.0) {
 		return NULL;
 	}
 
 	/* TODO: Add gdImageGetRowPtr and works with ptr at the row level
 	 * for the true color and palette images
 	 * new formats will simply work with ptr
	 */
	match = 1;
	for (y = 0; match && y < height; y++) {
		for (x = 0; match && x < width; x++) {
			match = (gdColorMatch(im, color, gdImageGetPixel(im, x,y), threshold)) > 0;
		}
	}

	/* Pierre
	 * Nothing to do > bye
	 * Duplicate the image?
	 */
	if (y == height - 1) {
		return NULL;
	}

	crop.y = y -1;
	match = 1;
	for (y = height - 1; match && y >= 0; y--) {
		for (x = 0; match && x < width; x++) {
			match = (gdColorMatch(im, color, gdImageGetPixel(im, x, y), threshold)) > 0;
		}
	}

	if (y == 0) {
		crop.height = height - crop.y + 1;
	} else {
		crop.height = y - crop.y + 2;
	}

	match = 1;
	for (x = 0; match && x < width; x++) {
		for (y = 0; match && y < crop.y + crop.height - 1; y++) {
			match = (gdColorMatch(im, color, gdImageGetPixel(im, x,y), threshold)) > 0;
		}
	}
	crop.x = x - 1;

	match = 1;
	for (x = width - 1; match && x >= 0; x--) {
		for (y = 0; match &&  y < crop.y + crop.height - 1; y++) {
			match = (gdColorMatch(im, color, gdImageGetPixel(im, x,y), threshold)) > 0;
		}
	}
	crop.width = x - crop.x + 2;

	return gdImageCrop(im, &crop);
}

/* ==== 真实标签：有漏洞（CWE-191） ==== */
static inline LineContribType * _gdContributionsAlloc(unsigned int line_length, unsigned int windows_size)
 {
 	unsigned int u = 0;
 	LineContribType *res;
	int overflow_error = 0;
 
 	res = (LineContribType *) gdMalloc(sizeof(LineContribType));
 	if (!res) {
 		return NULL;
	}
	res->WindowSize = windows_size;
	res->LineLength = line_length;
	if (overflow2(line_length, sizeof(ContributionType))) {
		gdFree(res);
		return NULL;
	}
	res->ContribRow = (ContributionType *) gdMalloc(line_length * sizeof(ContributionType));
	if (res->ContribRow == NULL) {
		gdFree(res);
 		return NULL;
 	}
 	for (u = 0 ; u < line_length ; u++) {
		if (overflow2(windows_size, sizeof(double))) {
			overflow_error = 1;
		} else {
			res->ContribRow[u].Weights = (double *) gdMalloc(windows_size * sizeof(double));
		}
		if (overflow_error == 1 || res->ContribRow[u].Weights == NULL) {
 			unsigned int i;
			u--;
			for (i=0;i<=u;i++) {
 				gdFree(res->ContribRow[i].Weights);
 			}
 			gdFree(res->ContribRow);
			gdFree(res);
			return NULL;
		}
	}
	return res;
}

/* ==== 真实标签：安全 ==== */
BGD_DECLARE(gdImagePtr) gdImageScale(const gdImagePtr src, const unsigned int new_width, const unsigned int new_height)
{
	gdImagePtr im_scaled = NULL;

	if (src == NULL || (uintmax_t)src->interpolation_id >= GD_METHOD_COUNT) {
		return NULL;
	}

	if (new_width == 0 || new_height == 0) {
		return NULL;
	}
	if (new_width == gdImageSX(src) && new_height == gdImageSY(src)) {
		return gdImageClone(src);
	}
	switch (src->interpolation_id) {
		/*Special cases, optimized implementations */
		case GD_NEAREST_NEIGHBOUR:
			im_scaled = gdImageScaleNearestNeighbour(src, new_width, new_height);
			break;

		case GD_BILINEAR_FIXED:
		case GD_LINEAR:
			im_scaled = gdImageScaleBilinear(src, new_width, new_height);
			break;

		case GD_BICUBIC_FIXED:
		case GD_BICUBIC:
			im_scaled = gdImageScaleBicubicFixed(src, new_width, new_height);
			break;

		/* generic */
		default:
			if (src->interpolation == NULL) {
				return NULL;
			}
			im_scaled = gdImageScaleTwoPass(src, new_width, new_height);
			break;
	}

	return im_scaled;
}

/* ==== 真实标签：安全 ==== */
static int bmp_read_8bit(gdImagePtr im, gdIOCtxPtr infile, bmp_info_t *info, bmp_hdr_t *header)
{
	int ypos = 0, xpos = 0, row = 0, index = 0;
	int padding = 0;

	if (info->enctype != BMP_BI_RGB && info->enctype != BMP_BI_RLE8) {
		return 1;
	}

	if (!info->numcolors) {
		info->numcolors = 256;
	} else if (info->numcolors < 0 || info->numcolors > 256) {
		return 1;
	}

	if (bmp_read_palette(im, infile, info->numcolors, (info->type == BMP_PALETTE_4))) {
		return 1;
	}

	im->colorsTotal = info->numcolors;

	/* There is a chance the data isn't until later, would be weird but it is possible */
	if (gdTell(infile) != header->off) {
		/* Should make sure we don't seek past the file size */
		if (!gdSeek(infile, header->off)) {
			return 1;
		}
	}

	/* The line must be divisible by 4, else its padded with NULLs */
	padding = (1 * info->width) % 4;
	if (padding) {
		padding = 4 - padding;
	}

	switch (info->enctype) {
	case BMP_BI_RGB:
		for (ypos = 0; ypos < info->height; ++ypos) {
			if (info->topdown) {
				row = ypos;
			} else {
				row = info->height - ypos - 1;
			}

			for (xpos = 0; xpos < info->width; ++xpos) {
				if (!gdGetByte(&index, infile)) {
					return 1;
				}

				if (im->open[index]) {
					im->open[index] = 0;
				}
				gdImageSetPixel(im, xpos, row, index);
			}
			/* Could create a new variable, but it isn't really worth it */
			for (xpos = padding; xpos > 0; --xpos) {
				if (!gdGetByte(&index, infile)) {
					return 1;
				}
			}
		}
		break;

	case BMP_BI_RLE8:
		if (bmp_read_rle(im, infile, info)) {
			return 1;
		}
		break;

	default:
		return 1;
	}
	return 0;
}
