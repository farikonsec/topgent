//! The draggable edge of a column.
//!
//! A widget rather than a `mouse_area`, because a press is not a drag. A
//! `mouse_area` reports that a button went down inside it and nothing else: it
//! does not know where it sits, so it cannot say how far the cursor has moved
//! since. Everything before this stepped a column one unit per click, which is
//! not what anyone means by resizing a column.
//!
//! This holds the cursor position it was pressed at, and emits the distance
//! moved since the last event. The caller turns pixels into a share of the
//! width, because only the caller knows how wide the table is.
//!
//! Grabbing is sticky. Once pressed, the widget keeps receiving movement until
//! the button is released, even when the cursor leaves its two-pixel body,
//! which it will immediately: a divider you lose the moment you start moving is
//! a divider nobody can drag.

use iced::advanced::layout::{self, Layout};
use iced::advanced::renderer;
use iced::advanced::widget::{self, Widget, tree};
use iced::advanced::{Clipboard, Shell};
use iced::{Color, Element, Event, Length, Rectangle, Size, mouse};

/// A vertical line the reader can drag sideways.
pub struct Divider<Message> {
    /// How tall the line is drawn.
    height: f32,
    /// The colour of the line at rest.
    colour: Color,
    /// The colour while it is being dragged or hovered.
    active: Color,
    /// Built from the pixels moved since the last event.
    on_drag: Box<dyn Fn(f32) -> Message>,
}

/// Where a drag started, or `None` when nothing is being dragged.
#[derive(Debug, Default, Clone, Copy)]
struct Grab {
    /// The cursor's x when the button went down, updated as it moves so each
    /// event carries a delta rather than a total.
    from: Option<f32>,
    /// Whether the cursor is over the line.
    over: bool,
}

/// The width of the line itself.
const LINE: f32 = 1.0;

/// How far either side of the line still counts as grabbing it.
///
/// A one-pixel target is one nobody hits. This is the same reason a window's
/// resize edge is wider than the border it draws.
const REACH: f32 = 3.0;

impl<Message> Divider<Message> {
    /// A divider that reports how far it has been dragged.
    pub fn new(
        height: f32,
        colour: Color,
        active: Color,
        on_drag: impl Fn(f32) -> Message + 'static,
    ) -> Self {
        Self {
            height,
            colour,
            active,
            on_drag: Box::new(on_drag),
        }
    }
}

impl<Message, Theme, Renderer> Widget<Message, Theme, Renderer> for Divider<Message>
where
    Renderer: renderer::Renderer,
{
    fn tag(&self) -> tree::Tag {
        tree::Tag::of::<Grab>()
    }

    fn state(&self) -> tree::State {
        tree::State::new(Grab::default())
    }

    fn size(&self) -> Size<Length> {
        Size::new(
            Length::Fixed(LINE + REACH * 2.0),
            Length::Fixed(self.height),
        )
    }

    fn layout(
        &mut self,
        _tree: &mut widget::Tree,
        _renderer: &Renderer,
        _limits: &layout::Limits,
    ) -> layout::Node {
        layout::Node::new(Size::new(LINE + REACH * 2.0, self.height))
    }

    fn update(
        &mut self,
        tree: &mut widget::Tree,
        event: &Event,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        _renderer: &Renderer,
        _clipboard: &mut dyn Clipboard,
        shell: &mut Shell<'_, Message>,
        _viewport: &Rectangle,
    ) {
        let grab = tree.state.downcast_mut::<Grab>();
        grab.over = cursor.is_over(layout.bounds());

        match event {
            Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) if grab.over => {
                grab.from = cursor.position().map(|p| p.x);
                // Captured, so the rest of the interface does not also act on
                // this press.
                shell.capture_event();
            }
            Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                // Deliberately not gated on the cursor still being over the
                // line. It leaves the moment the drag starts.
                if let (Some(from), Some(now)) = (grab.from, cursor.position().map(|p| p.x)) {
                    let moved = now - from;
                    if moved.abs() >= 1.0 {
                        grab.from = Some(now);
                        shell.publish((self.on_drag)(moved));
                        shell.capture_event();
                    }
                }
            }
            Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                grab.from = None;
            }
            _ => {}
        }
    }

    fn mouse_interaction(
        &self,
        tree: &widget::Tree,
        _layout: Layout<'_>,
        _cursor: mouse::Cursor,
        _viewport: &Rectangle,
        _renderer: &Renderer,
    ) -> mouse::Interaction {
        let grab = tree.state.downcast_ref::<Grab>();
        if grab.from.is_some() || grab.over {
            mouse::Interaction::ResizingHorizontally
        } else {
            mouse::Interaction::default()
        }
    }

    fn draw(
        &self,
        tree: &widget::Tree,
        renderer: &mut Renderer,
        _theme: &Theme,
        _style: &renderer::Style,
        layout: Layout<'_>,
        _cursor: mouse::Cursor,
        _viewport: &Rectangle,
    ) {
        let grab = tree.state.downcast_ref::<Grab>();
        let bounds = layout.bounds();
        // The line is drawn one pixel wide in the middle of a wider target, so
        // the thing you see is thin and the thing you hit is not.
        let line = Rectangle {
            x: bounds.x + REACH,
            y: bounds.y,
            width: LINE,
            height: bounds.height,
        };
        let lit = grab.from.is_some() || grab.over;
        renderer.fill_quad(
            renderer::Quad {
                bounds: line,
                ..renderer::Quad::default()
            },
            if lit { self.active } else { self.colour },
        );
    }
}

impl<'a, Message, Theme, Renderer> From<Divider<Message>> for Element<'a, Message, Theme, Renderer>
where
    Message: 'a,
    Theme: 'a,
    Renderer: renderer::Renderer + 'a,
{
    fn from(divider: Divider<Message>) -> Self {
        Self::new(divider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-pixel target is one nobody hits, which is why the first attempt
    /// at this was a click that stepped a width instead of a drag.
    const _: () = assert!(REACH > 0.0 && LINE + REACH * 2.0 >= 6.0);

    /// A grab is what makes this a drag rather than a click: it holds where
    /// the cursor was, and every movement is measured against it.
    #[test]
    fn a_grab_holds_where_it_began_and_lets_go() {
        let mut grab = Grab::default();
        assert!(grab.from.is_none(), "a divider starts un-grabbed");
        grab.from = Some(120.0);
        assert_eq!(grab.from, Some(120.0));
        grab.from = None;
        assert!(grab.from.is_none(), "releasing must end the grab");
    }
}
