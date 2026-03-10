#include "hb-fuzzer.hh"

#include <hb.h>
#include <hb-ot.h>

/* ---- Draw callbacks ---- */

static void
_move_to (hb_draw_funcs_t *, void *data, hb_draw_state_t *,
	  float x, float y, void *)
{
  *(float *) data += x + y;
}

static void
_line_to (hb_draw_funcs_t *, void *data, hb_draw_state_t *,
	  float x, float y, void *)
{
  *(float *) data += x + y;
}

static void
_quadratic_to (hb_draw_funcs_t *, void *data, hb_draw_state_t *,
	       float cx, float cy, float x, float y, void *)
{
  *(float *) data += cx + cy + x + y;
}

static void
_cubic_to (hb_draw_funcs_t *, void *data, hb_draw_state_t *,
	   float c1x, float c1y, float c2x, float c2y,
	   float x, float y, void *)
{
  *(float *) data += c1x + c1y + c2x + c2y + x + y;
}

static void
_close_path (hb_draw_funcs_t *, void *, hb_draw_state_t *, void *)
{
}

/* ---- Paint callbacks ---- */

static void
_push_transform (hb_paint_funcs_t *, void *data,
		 float, float, float, float, float, float, void *)
{
  (*(unsigned *) data)++;
}

static void
_pop_transform (hb_paint_funcs_t *, void *data, void *)
{
  (*(unsigned *) data)++;
}

static hb_bool_t
_color_glyph (hb_paint_funcs_t *, void *, hb_codepoint_t, hb_font_t *, void *)
{
  return false;
}

static void
_push_clip_glyph (hb_paint_funcs_t *, void *data,
		  hb_codepoint_t, hb_font_t *, void *)
{
  (*(unsigned *) data)++;
}

static void
_push_clip_rectangle (hb_paint_funcs_t *, void *data,
		      float, float, float, float, void *)
{
  (*(unsigned *) data)++;
}

static void
_pop_clip (hb_paint_funcs_t *, void *data, void *)
{
  (*(unsigned *) data)++;
}

static void
_color (hb_paint_funcs_t *, void *data, hb_bool_t, hb_color_t color, void *)
{
  *(unsigned *) data += hb_color_get_alpha (color);
}

static hb_bool_t
_image (hb_paint_funcs_t *, void *data, hb_blob_t *image,
	unsigned, unsigned, hb_tag_t, float, hb_glyph_extents_t *, void *)
{
  unsigned len = 0;
  hb_blob_get_data (image, &len);
  *(unsigned *) data += len;
  return true;
}

static void
_read_color_line (hb_color_line_t *cl, unsigned *ops)
{
  unsigned total = hb_color_line_get_color_stops (cl, 0, nullptr, nullptr);
  *ops += total;

  hb_color_stop_t stops[8];
  unsigned count = sizeof (stops) / sizeof (stops[0]);
  if (count > total) count = total;
  hb_color_line_get_color_stops (cl, 0, &count, stops);
  for (unsigned i = 0; i < count; i++)
    *ops += hb_color_get_alpha (stops[i].color);

  hb_color_line_get_extend (cl);
}

static void
_linear_gradient (hb_paint_funcs_t *, void *data, hb_color_line_t *cl,
		  float, float, float, float, float, float, void *)
{
  _read_color_line (cl, (unsigned *) data);
}

static void
_radial_gradient (hb_paint_funcs_t *, void *data, hb_color_line_t *cl,
		  float, float, float, float, float, float, void *)
{
  _read_color_line (cl, (unsigned *) data);
}

static void
_sweep_gradient (hb_paint_funcs_t *, void *data, hb_color_line_t *cl,
		 float, float, float, float, void *)
{
  _read_color_line (cl, (unsigned *) data);
}

static void
_push_group (hb_paint_funcs_t *, void *data, void *)
{
  (*(unsigned *) data)++;
}

static void
_pop_group (hb_paint_funcs_t *, void *data, hb_paint_composite_mode_t, void *)
{
  (*(unsigned *) data)++;
}

static hb_bool_t
_custom_palette_color (hb_paint_funcs_t *, void *, unsigned, hb_color_t *, void *)
{
  return false;
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  _fuzzing_skip_leading_comment (&data, &size);
  alloc_state = _fuzzing_alloc_state (data, size);

  hb_blob_t *blob = hb_blob_create ((const char *) data, size,
				    HB_MEMORY_MODE_READONLY, nullptr, nullptr);
  hb_face_t *face = hb_face_create (blob, 0);
  hb_font_t *font = hb_font_create (face);

  /* Set up draw funcs with actual callbacks */
  hb_draw_funcs_t *dfuncs = hb_draw_funcs_create ();
  hb_draw_funcs_set_move_to_func (dfuncs, _move_to, nullptr, nullptr);
  hb_draw_funcs_set_line_to_func (dfuncs, _line_to, nullptr, nullptr);
  hb_draw_funcs_set_quadratic_to_func (dfuncs, _quadratic_to, nullptr, nullptr);
  hb_draw_funcs_set_cubic_to_func (dfuncs, _cubic_to, nullptr, nullptr);
  hb_draw_funcs_set_close_path_func (dfuncs, _close_path, nullptr, nullptr);

  /* Set up paint funcs with all callbacks */
  hb_paint_funcs_t *pfuncs = hb_paint_funcs_create ();
  hb_paint_funcs_set_push_transform_func (pfuncs, _push_transform, nullptr, nullptr);
  hb_paint_funcs_set_pop_transform_func (pfuncs, _pop_transform, nullptr, nullptr);
  hb_paint_funcs_set_color_glyph_func (pfuncs, _color_glyph, nullptr, nullptr);
  hb_paint_funcs_set_push_clip_glyph_func (pfuncs, _push_clip_glyph, nullptr, nullptr);
  hb_paint_funcs_set_push_clip_rectangle_func (pfuncs, _push_clip_rectangle, nullptr, nullptr);
  hb_paint_funcs_set_pop_clip_func (pfuncs, _pop_clip, nullptr, nullptr);
  hb_paint_funcs_set_color_func (pfuncs, _color, nullptr, nullptr);
  hb_paint_funcs_set_image_func (pfuncs, _image, nullptr, nullptr);
  hb_paint_funcs_set_linear_gradient_func (pfuncs, _linear_gradient, nullptr, nullptr);
  hb_paint_funcs_set_radial_gradient_func (pfuncs, _radial_gradient, nullptr, nullptr);
  hb_paint_funcs_set_sweep_gradient_func (pfuncs, _sweep_gradient, nullptr, nullptr);
  hb_paint_funcs_set_push_group_func (pfuncs, _push_group, nullptr, nullptr);
  hb_paint_funcs_set_pop_group_func (pfuncs, _pop_group, nullptr, nullptr);
  hb_paint_funcs_set_custom_palette_color_func (pfuncs, _custom_palette_color, nullptr, nullptr);

  volatile float draw_result = 0;
  volatile unsigned paint_result = 0;

  unsigned glyph_count = hb_face_get_glyph_count (face);
  unsigned limit = glyph_count > 64 ? 64 : glyph_count;

  for (unsigned gid = 0; gid < limit; gid++)
  {
    float draw_sum = 0;
    hb_font_draw_glyph (font, gid, dfuncs, &draw_sum);
    draw_result += draw_sum;

    hb_glyph_extents_t extents;
    hb_font_get_glyph_extents (font, gid, &extents);
    draw_result += extents.width + extents.height;

    unsigned paint_ops = 0;
    hb_font_paint_glyph (font, gid, pfuncs, &paint_ops, 0, HB_COLOR (0, 0, 0, 255));
    paint_result += paint_ops;
  }

  /* Also try palette index 1 on the first glyph */
  if (limit > 0)
  {
    unsigned paint_ops = 0;
    hb_font_paint_glyph (font, 0, pfuncs, &paint_ops, 1, HB_COLOR (255, 0, 0, 255));
    paint_result += paint_ops;
  }

  hb_draw_funcs_destroy (dfuncs);
  hb_paint_funcs_destroy (pfuncs);
  hb_font_destroy (font);
  hb_face_destroy (face);
  hb_blob_destroy (blob);

  return (draw_result || paint_result) ? 0 : 0;
}
