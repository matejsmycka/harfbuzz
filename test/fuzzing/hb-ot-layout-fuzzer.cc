#include "hb-fuzzer.hh"

#include <hb.h>
#include <hb-ot.h>

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  _fuzzing_skip_leading_comment (&data, &size);
  alloc_state = _fuzzing_alloc_state (data, size);

  hb_blob_t *blob = hb_blob_create ((const char *) data, size,
				    HB_MEMORY_MODE_READONLY, nullptr, nullptr);
  hb_face_t *face = hb_face_create (blob, 0);
  hb_font_t *font = hb_font_create (face);

  volatile unsigned counter = 0;

  for (unsigned table_idx = 0; table_idx < 2; table_idx++)
  {
    hb_tag_t table_tag = table_idx == 0 ? HB_OT_TAG_GSUB : HB_OT_TAG_GPOS;

    /* Enumerate scripts */
    hb_tag_t script_tags[16];
    unsigned script_count = sizeof (script_tags) / sizeof (script_tags[0]);
    hb_ot_layout_table_get_script_tags (face, table_tag, 0, &script_count, script_tags);
    counter += script_count;

    unsigned script_limit = script_count > 4 ? 4 : script_count;
    for (unsigned s = 0; s < script_limit; s++)
    {
      /* Enumerate languages per script */
      hb_tag_t lang_tags[16];
      unsigned lang_count = sizeof (lang_tags) / sizeof (lang_tags[0]);
      hb_ot_layout_script_get_language_tags (face, table_tag, s, 0, &lang_count, lang_tags);
      counter += lang_count;

      unsigned lang_limit = lang_count > 4 ? 4 : lang_count;
      for (unsigned l = 0; l < lang_limit; l++)
      {
	/* Enumerate features per language */
	hb_tag_t feat_tags[16];
	unsigned feat_count = sizeof (feat_tags) / sizeof (feat_tags[0]);
	hb_ot_layout_language_get_feature_tags (face, table_tag, s, l, 0, &feat_count, feat_tags);
	counter += feat_count;

	unsigned feat_indexes[16];
	unsigned feat_idx_count = sizeof (feat_indexes) / sizeof (feat_indexes[0]);
	hb_ot_layout_language_get_feature_indexes (face, table_tag, s, l, 0, &feat_idx_count, feat_indexes);
	counter += feat_idx_count;

	/* Required feature */
	unsigned req_index;
	hb_tag_t req_tag;
	hb_ot_layout_language_get_required_feature (face, table_tag, s, l, &req_index, &req_tag);
	counter += req_index;
      }
    }

    /* Collect all features and lookups */
    hb_set_t *feature_indices = hb_set_create ();
    hb_ot_layout_collect_features (face, table_tag, nullptr, nullptr, nullptr, feature_indices);
    counter += hb_set_get_population (feature_indices);

    hb_set_t *lookup_indices = hb_set_create ();
    hb_ot_layout_collect_lookups (face, table_tag, nullptr, nullptr, nullptr, lookup_indices);
    counter += hb_set_get_population (lookup_indices);

    /* Collect glyphs from first few lookups */
    hb_codepoint_t lookup_idx = HB_SET_VALUE_INVALID;
    unsigned lookup_limit = 0;
    while (hb_set_next (lookup_indices, &lookup_idx) && lookup_limit < 8)
    {
      hb_set_t *glyphs_before = hb_set_create ();
      hb_set_t *glyphs_input = hb_set_create ();
      hb_set_t *glyphs_after = hb_set_create ();
      hb_set_t *glyphs_output = hb_set_create ();

      hb_ot_layout_lookup_collect_glyphs (face, table_tag, lookup_idx,
					  glyphs_before, glyphs_input,
					  glyphs_after, glyphs_output);
      counter += hb_set_get_population (glyphs_input);
      counter += hb_set_get_population (glyphs_output);

      hb_set_destroy (glyphs_before);
      hb_set_destroy (glyphs_input);
      hb_set_destroy (glyphs_after);
      hb_set_destroy (glyphs_output);
      lookup_limit++;
    }

    /* Get lookups for first few features */
    hb_codepoint_t feat_idx = HB_SET_VALUE_INVALID;
    unsigned feat_limit = 0;
    while (hb_set_next (feature_indices, &feat_idx) && feat_limit < 8)
    {
      unsigned lookups[16];
      unsigned lookup_count = sizeof (lookups) / sizeof (lookups[0]);
      hb_ot_layout_feature_get_lookups (face, table_tag, feat_idx, 0, &lookup_count, lookups);
      counter += lookup_count;
      feat_limit++;
    }

    hb_set_destroy (feature_indices);
    hb_set_destroy (lookup_indices);
  }

  /* GDEF glyph classes */
  hb_ot_layout_has_glyph_classes (face);
  unsigned glyph_count = hb_face_get_glyph_count (face);
  unsigned glyph_limit = glyph_count > 32 ? 32 : glyph_count;
  for (unsigned gid = 0; gid < glyph_limit; gid++)
  {
    counter += hb_ot_layout_get_glyph_class (face, gid);

    unsigned caret_count = 8;
    hb_position_t carets[8];
    hb_ot_layout_get_ligature_carets (font, HB_DIRECTION_LTR, gid, 0, &caret_count, carets);
    counter += caret_count;
  }

  /* Baselines */
  static const hb_ot_layout_baseline_tag_t baselines[] = {
    HB_OT_LAYOUT_BASELINE_TAG_ROMAN,
    HB_OT_LAYOUT_BASELINE_TAG_HANGING,
    HB_OT_LAYOUT_BASELINE_TAG_IDEO_FACE_BOTTOM_OR_LEFT,
    HB_OT_LAYOUT_BASELINE_TAG_IDEO_FACE_TOP_OR_RIGHT,
    HB_OT_LAYOUT_BASELINE_TAG_IDEO_EMBOX_BOTTOM_OR_LEFT,
    HB_OT_LAYOUT_BASELINE_TAG_IDEO_EMBOX_TOP_OR_RIGHT,
    HB_OT_LAYOUT_BASELINE_TAG_MATH,
  };
  for (unsigned i = 0; i < sizeof (baselines) / sizeof (baselines[0]); i++)
  {
    hb_position_t pos;
    hb_ot_layout_get_baseline (font, baselines[i],
			       HB_DIRECTION_LTR, HB_SCRIPT_LATIN, HB_TAG_NONE, &pos);
    hb_ot_layout_get_baseline (font, baselines[i],
			       HB_DIRECTION_RTL, HB_SCRIPT_ARABIC, HB_TAG_NONE, &pos);
  }

  hb_font_destroy (font);
  hb_face_destroy (face);
  hb_blob_destroy (blob);

  return counter ? 0 : 0;
}
