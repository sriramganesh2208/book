import Hotel from "../models/Hotel.js";
import Room from "../models/Room.js";

export const createHotel = async (req, res, next) => {
  const newHotel = new Hotel(req.body);

  try {
    const savedHotel = await newHotel.save();
    res.status(200).json(savedHotel);
  } catch (err) {
    next(err);
  }
};

export const updateHotel = async (req, res, next) => {
  try {
    const updatedHotel = await Hotel.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true }
    );
    res.status(200).json(updatedHotel);
  } catch (err) {
    next(err);
  }
};

export const deleteHotel = async (req, res, next) => {
  try {
    await Hotel.findByIdAndDelete(req.params.id);
    res.status(200).json("Hotel has been deleted.");
  } catch (err) {
    next(err);
  }
};

export const getHotel = async (req, res, next) => {
  try {
    const hotel = await Hotel.findById(req.params.id);
    res.status(200).json(hotel);
  } catch (err) {
    next(err);
  }
};

export const getHotels = async (req, res, next) => {
  const { min, max, sort, ...others } = req.query;
  try {
    let sortOption = {};

    // Define sort option based on the query parameter
    if (sort === "lowToHigh") {
      sortOption = { cheapestPrice: 1 }; // Sort by price low to high
    } else if (sort === "highToLow") {
      sortOption = { cheapestPrice: -1 }; // Sort by price high to low
    }

    let priceRangeQuery = {};

    // Define price range query based on the price range selected
    if (min && max) {
      priceRangeQuery = { cheapestPrice: { $gte: min, $lte: max } };
    } else {
      switch (max) {
        case '2000':
          priceRangeQuery = { cheapestPrice: { $lte: 2000 } };
          break;
        case '4000':
          priceRangeQuery = { cheapestPrice: { $gte: 2001, $lte: 4000 } };
          break;
        case '6000':
          priceRangeQuery = { cheapestPrice: { $gte: 4001, $lte: 6000 } };
          break;
        default:
          priceRangeQuery = { cheapestPrice: { $gte: 6001 } };
          break;
      }
    }

    const hotels = await Hotel.find({
      ...others,
      ...priceRangeQuery,
    })
      .sort(sortOption) // Apply sorting option
      .limit(req.query.limit);

    res.status(200).json(hotels);
  } catch (err) {
    next(err);
  }
};


export const countByCity = async (req, res, next) => {
  const cities = req.query.cities.split(",");
  try {
    const list = await Promise.all(
      cities.map((city) => {
        return Hotel.countDocuments({ city: city });
      })
    );
    res.status(200).json(list);
  } catch (err) {
    next(err);
  }
};

export const countByType = async (req, res, next) => {
  try {
    const hotelCount = await Hotel.countDocuments({ type: "hotel" });
    const apartmentCount = await Hotel.countDocuments({ type: "apartment" });
    const resortCount = await Hotel.countDocuments({ type: "resort" });
    const villaCount = await Hotel.countDocuments({ type: "villa" });
    const cabinCount = await Hotel.countDocuments({ type: "cabin" });

    res.status(200).json([
      { type: "hotel", count: hotelCount },
      { type: "apartments", count: apartmentCount },
      { type: "resorts", count: resortCount },
      { type: "villas", count: villaCount },
      { type: "cabins", count: cabinCount },
    ]);
  } catch (err) {
    next(err);
  }
};

export const getHotelRooms = async (req, res, next) => {
  try {
    const hotel = await Hotel.findById(req.params.id);
    const list = await Promise.all(
      hotel.rooms.map((room) => {
        return Room.findById(room);
      })
    );
    res.status(200).json(list)
  } catch (err) {
    next(err);
  }
};
